package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pabotesu/hulegu/pkg/protocol"
	"github.com/pabotesu/hulegu/pkg/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// エラー定義
var (
	ErrNotConnected     = errors.New("client: not connected to server")
	ErrAlreadyConnected = errors.New("client: already connected")
)

// Config はHuleguクライアントの設定です
type Config struct {
	ServerURL       string        // サーバーのWebSocketURL
	InterfaceName   string        // WireGuardインターフェース名
	ListenAddrBase  string        // ローカルUDPリスンのベースアドレス
	PingInterval    time.Duration // キープアライブping間隔
	ReconnectDelay  time.Duration // 再接続の遅延
	MaxRetries      int           // 再接続の最大試行回数（負数は無制限）
	HandshakeExpiry time.Duration // ハンドシェイクの期限切れ時間
}

// DefaultConfig はデフォルト設定を返します
func DefaultConfig() *Config {
	return &Config{
		ServerURL:       "ws://localhost:8080/ws",
		InterfaceName:   "wg0",
		ListenAddrBase:  "",
		PingInterval:    30 * time.Second,
		ReconnectDelay:  5 * time.Second,
		MaxRetries:      -1,
		HandshakeExpiry: 3 * time.Minute,
	}
}

// Client はHuleguクライアントです
type Client struct {
	config    *Config
	wg        *wireguard.Manager
	conn      *websocket.Conn
	publicKey wgtypes.Key

	endpoints    map[wgtypes.Key]*HuleguEndpoint
	enabledPeers map[wgtypes.Key]bool

	sessionID string
	packetID  uint32

	ctx        context.Context
	cancelFunc context.CancelFunc

	connected bool
	connMu    sync.RWMutex
	peerMu    sync.RWMutex

	reconnectMu sync.Mutex
}

// New は新しいHuleguクライアントを作成します
func New(config *Config) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// WireGuardマネージャーの初期化
	wg, err := wireguard.New(config.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize WireGuard: %w", err)
	}

	// コンテキストの作成
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		config:       config,
		wg:           wg,
		publicKey:    wg.GetPublicKey(),
		endpoints:    make(map[wgtypes.Key]*HuleguEndpoint),
		enabledPeers: make(map[wgtypes.Key]bool),
		ctx:          ctx,
		cancelFunc:   cancel,
	}

	return client, nil
}

// Connect はサーバーとの接続を確立します
func (c *Client) Connect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.connected {
		return ErrAlreadyConnected
	}

	// WebSocketサーバーに接続
	u, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	log.Printf("Connecting to server: %s", u.String())

	// WebSocket接続の確立
	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = c.config.HandshakeExpiry

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("WebSocket connection failed: %w", err)
	}

	c.conn = conn

	// ハンドシェイクを実行
	handshakeData := &protocol.HandshakeData{
		PublicKey: c.publicKey,
		Version:   protocol.ProtocolVersion,
		Timestamp: time.Now().UnixNano(),
	}

	handshakePayload, err := protocol.EncodeHandshake(handshakeData)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to encode handshake: %w", err)
	}

	msg := &protocol.Message{
		Type:    protocol.TypeHandshake,
		Payload: handshakePayload,
	}

	msgBytes, err := protocol.EncodeMessage(msg)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to encode message: %w", err)
	}

	err = conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// ハンドシェイク応答の待機
	conn.SetReadDeadline(time.Now().Add(c.config.HandshakeExpiry))
	defer conn.SetReadDeadline(time.Time{})

	_, respData, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to receive handshake response: %w", err)
	}

	// メッセージのデコード
	respMsg, err := protocol.DecodeMessage(respData)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to decode handshake response: %w", err)
	}

	if respMsg.Type != protocol.TypeHandshakeAck {
		conn.Close()
		return fmt.Errorf("unexpected response type: %d", respMsg.Type)
	}

	// ハンドシェイク応答のデコード
	ackData, err := protocol.DecodeHandshakeAck(respMsg.Payload)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to decode handshake ack: %w", err)
	}

	// セッションIDの保存
	c.sessionID = ackData.SessionID
	c.connected = true

	log.Printf("Handshake successful, session established: %s", c.sessionID)

	// 読み込みループを開始
	go c.websocketReadLoop()
	go c.packetForwardingLoop()

	return nil
}

// websocketReadLoop はWebSocketからのパケットを受信してWireGuardに転送します
func (c *Client) websocketReadLoop() {
	pingTicker := time.NewTicker(c.config.PingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-pingTicker.C:
			// キープアライブping送信
			c.sendPing()
		default:
			c.connMu.RLock()
			conn := c.conn
			connected := c.connected
			c.connMu.RUnlock()

			if !connected || conn == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			_, message, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Failed to read from WebSocket: %v", err)
				c.reconnect()
				return
			}

			// メッセージ処理
			c.handleWebSocketMessage(message)
		}
	}
}

// sendPing はキープアライブpingを送信します
func (c *Client) sendPing() error {
	c.connMu.RLock()
	defer c.connMu.RUnlock()

	if !c.connected || c.conn == nil {
		return ErrNotConnected
	}

	// Pingメッセージの作成と送信
	pingData := &protocol.PingData{
		Timestamp: time.Now().UnixNano(),
		Sequence:  uint32(time.Now().Unix()),
	}

	pingPayload, err := protocol.EncodePing(pingData)
	if err != nil {
		return fmt.Errorf("failed to encode ping: %w", err)
	}

	msg := &protocol.Message{
		Type:    protocol.TypePing,
		Payload: pingPayload,
	}

	msgBytes, err := protocol.EncodeMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	err = c.conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	return nil
}

// reconnect はサーバーに再接続します
func (c *Client) reconnect() {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	c.connMu.RLock()
	if !c.connected {
		c.connMu.RUnlock()
		return
	}
	c.connMu.RUnlock()

	// 現在有効なピアのリストを保存
	c.peerMu.RLock()
	enabledPeers := make([]wgtypes.Key, 0, len(c.enabledPeers))
	for key := range c.enabledPeers {
		enabledPeers = append(enabledPeers, key)
	}
	c.peerMu.RUnlock()

	// 現在の接続を閉じる
	c.Disconnect()

	// 再接続を試行
	retries := 0
	for c.config.MaxRetries < 0 || retries < c.config.MaxRetries {
		log.Printf("Attempting to reconnect (%d)...", retries+1)
		time.Sleep(c.config.ReconnectDelay)

		err := c.Connect()
		if err == nil {
			log.Printf("Successfully reconnected")

			// 以前有効だったピアを再度有効化
			for _, peerKey := range enabledPeers {
				if err := c.setupEndpointForPeer(peerKey); err != nil {
					log.Printf("Failed to re-enable peer %s: %v", peerKey.String(), err)
				} else {
					c.peerMu.Lock()
					c.enabledPeers[peerKey] = true
					c.peerMu.Unlock()
				}
			}

			return
		}

		log.Printf("Reconnection failed: %v", err)
		retries++
	}

	log.Printf("Max reconnection attempts reached (%d)", c.config.MaxRetries)
}

// handleWebSocketMessage はサーバーからのメッセージを処理します
func (c *Client) handleWebSocketMessage(data []byte) {
	// メッセージのデコード
	msg, err := protocol.DecodeMessage(data)
	if err != nil {
		log.Printf("Failed to decode message: %v", err)
		return
	}

	if msg.Type == protocol.TypePacket {
		// パケットデータのデコード
		packet, err := protocol.DecodePacket(msg.Payload)
		if err != nil {
			log.Printf("Failed to decode packet data: %v", err)
			return
		}

		log.Printf("Received packet from server: sourceKey=%s, packetID=%d",
			packet.SourceKey.String(), packet.PacketID)

		// パケットをWireGuardに転送
		c.handleWebSocketPacket(packet.PacketData, packet.SourceKey)
	}
}

// handleWebSocketPacket はWebSocketから受信したパケットをWireGuardに転送します
func (c *Client) handleWebSocketPacket(packetData []byte, sourceKey wgtypes.Key) {
	// IPヘッダー解析（デバッグ用）
	if len(packetData) >= 20 {
		version := packetData[0] >> 4
		if version == 4 {
			srcIP := net.IP(packetData[12:16]).String()
			dstIP := net.IP(packetData[16:20]).String()
			log.Printf("IPv4 packet: src=%s, dst=%s from peer %s",
				srcIP, dstIP, sourceKey.String())
		}
	}

	// 送信元ピア用のエンドポイントを取得
	c.peerMu.RLock()
	endpoint, exists := c.endpoints[sourceKey]
	c.peerMu.RUnlock()

	if exists && endpoint != nil {
		// エンドポイント経由でWireGuardに転送
		n, err := endpoint.WriteToWireGuard(packetData)
		if err != nil {
			log.Printf("ERROR: Failed to forward packet via endpoint: %v", err)
		} else {
			log.Printf("Successfully forwarded %d bytes via endpoint for peer %s", n, sourceKey.String())
		}
	} else {
		log.Printf("No endpoint found for peer %s", sourceKey.String())
	}
}

// Disconnect はサーバーとの接続を切断します
func (c *Client) Disconnect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if !c.connected {
		return ErrNotConnected
	}

	// WebSocket接続を閉じる
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	// すべてのエンドポイントをクローズ
	c.peerMu.Lock()
	for peerKey, endpoint := range c.endpoints {
		if endpoint != nil {
			endpoint.Close()
			log.Printf("Closed endpoint for peer %s", peerKey.String())
		}
	}
	c.peerMu.Unlock()

	c.connected = false
	c.sessionID = ""
	log.Printf("Disconnected from server")
	return nil
}

// Close はクライアントのリソースを解放します
func (c *Client) Close() error {
	c.cancelFunc()

	if c.connected {
		c.Disconnect()
	}

	c.peerMu.Lock()
	for peerKey, endpoint := range c.endpoints {
		if endpoint != nil {
			endpoint.Close()
		}
		delete(c.endpoints, peerKey)
	}
	c.enabledPeers = make(map[wgtypes.Key]bool)
	c.peerMu.Unlock()

	if c.wg != nil {
		c.wg.Close()
	}

	return nil
}

// packetForwardingLoop はエンドポイントからのパケットを処理します
func (c *Client) packetForwardingLoop() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			c.connMu.RLock()
			connected := c.connected
			c.connMu.RUnlock()

			if !connected {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// 現在のエンドポイントリストを取得
			c.peerMu.RLock()
			endpointsCopy := make(map[wgtypes.Key]*HuleguEndpoint)
			for key, endpoint := range c.endpoints {
				if endpoint != nil {
					endpointsCopy[key] = endpoint
				}
			}
			c.peerMu.RUnlock()

			// 各エンドポイントからのパケットを処理
			for peerKey, endpoint := range endpointsCopy {
				packet, err := endpoint.ReadPacket()
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					continue
				}

				// パケットをサーバーに転送
				if endpoint.IsFromWireGuard(packet) {
					// パケット転送
					c.forwardPacketToServer(packet.Data, peerKey)
				}
			}

			time.Sleep(5 * time.Millisecond)
		}
	}
}

// forwardPacketToServer はパケットをサーバーに転送します
func (c *Client) forwardPacketToServer(packetData []byte, peerKey wgtypes.Key) error {
	c.connMu.RLock()
	defer c.connMu.RUnlock()

	if !c.connected || c.conn == nil {
		return ErrNotConnected
	}

	// パケットIDの生成
	c.packetID++

	log.Printf("Forwarding packet to server for peer %s, packetID=%d, size=%d bytes",
		peerKey.String(), c.packetID, len(packetData))

	// パケットデータの作成
	packet := &protocol.PacketData{
		TargetKey:  peerKey,
		SourceKey:  c.publicKey,
		PacketID:   c.packetID,
		PacketData: packetData,
	}

	// パケットデータのエンコード
	packetPayload, err := protocol.EncodePacket(packet)
	if err != nil {
		return fmt.Errorf("failed to encode packet: %w", err)
	}

	// メッセージの作成
	msg := &protocol.Message{
		Type:    protocol.TypePacket,
		Payload: packetPayload,
	}

	// メッセージのエンコード
	msgBytes, err := protocol.EncodeMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// WebSocketでの送信
	err = c.conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	return nil
}

// EnablePeer はピアをHuleguで有効化します
func (c *Client) EnablePeer(peerKeyStr string) error {
	peerKey, err := wgtypes.ParseKey(peerKeyStr)
	if err != nil {
		return fmt.Errorf("invalid peer key: %w", err)
	}

	c.peerMu.Lock()
	defer c.peerMu.Unlock()

	// すでにピアが有効化されているか確認
	if _, exists := c.enabledPeers[peerKey]; exists {
		return fmt.Errorf("peer %s is already enabled", peerKeyStr)
	}

	// ピアがWireGuardの設定に存在するか確認
	err = c.wg.RefreshDeviceInfo()
	if err != nil {
		return fmt.Errorf("failed to refresh device info: %w", err)
	}

	found := false
	for _, peer := range c.wg.GetPeers() {
		if peer.PublicKey == peerKey {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("peer %s not found in WireGuard configuration", peerKeyStr)
	}

	// エンドポイントの作成
	err = c.setupEndpointForPeer(peerKey)
	if err != nil {
		return fmt.Errorf("failed to setup endpoint for peer %s: %w", peerKeyStr, err)
	}

	// 有効なピアリストに追加
	c.enabledPeers[peerKey] = true

	log.Printf("Peer %s enabled for Hulegu", peerKeyStr)
	return nil
}

// DisablePeer はピアのHulegu使用を無効化します
func (c *Client) DisablePeer(peerKeyStr string) error {
	peerKey, err := wgtypes.ParseKey(peerKeyStr)
	if err != nil {
		return fmt.Errorf("invalid peer key: %w", err)
	}

	c.peerMu.Lock()
	defer c.peerMu.Unlock()

	// ピアが有効化されているか確認
	if _, exists := c.enabledPeers[peerKey]; !exists {
		return fmt.Errorf("peer %s is not enabled", peerKeyStr)
	}

	// エンドポイントをクローズ
	if endpoint, exists := c.endpoints[peerKey]; exists && endpoint != nil {
		endpoint.Close()
		delete(c.endpoints, peerKey)
	}

	// 有効なピアリストから削除
	delete(c.enabledPeers, peerKey)

	log.Printf("Peer %s disabled for Hulegu", peerKeyStr)
	return nil
}

// setupEndpointForPeer は特定のピア用のエンドポイントを設定します
func (c *Client) setupEndpointForPeer(peerKey wgtypes.Key) error {
	// WireGuardインターフェースの情報を取得
	port := c.wg.GetListenPort()
	if port == 0 {
		return fmt.Errorf("WireGuard listen port not configured")
	}

	// WireGuardのエンドポイントアドレス
	wgEndpoint := fmt.Sprintf("127.0.0.1:%d", port)

	// リスニングアドレスの設定
	listenAddr := c.config.ListenAddrBase
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0" // OSに空きポートを割り当て
	}

	// 以前のエンドポイントがあれば閉じる
	if oldEndpoint, exists := c.endpoints[peerKey]; exists && oldEndpoint != nil {
		oldEndpoint.Close()
	}

	// HuleguEndpointの作成
	endpoint, err := NewHuleguEndpoint(listenAddr, wgEndpoint)
	if err != nil {
		return fmt.Errorf("failed to create endpoint: %w", err)
	}

	c.endpoints[peerKey] = endpoint

	// エンドポイントのローカルアドレス情報をログ出力
	localAddr := endpoint.LocalAddr().(*net.UDPAddr)
	log.Printf("Hulegu endpoint for peer %s listening on %s", peerKey, localAddr.String())

	// ここで対象ピアのエンドポイントを更新 - この部分が重要
	err = c.wg.UpdatePeerEndpoint(peerKey, localAddr)
	if err != nil {
		// エンドポイントをクローズして戻す
		endpoint.Close()
		delete(c.endpoints, peerKey)
		return fmt.Errorf("failed to update WireGuard peer endpoint: %w", err)
	}

	log.Printf("Created Hulegu endpoint for peer %s", peerKey)
	return nil
}
