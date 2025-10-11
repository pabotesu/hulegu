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
	ErrHandshakeFailed  = errors.New("client: handshake failed")
)

// Config はHuleguクライアントの設定です
type Config struct {
	ServerURL       string        // サーバーのWebSocketURL
	InterfaceName   string        // WireGuardインターフェース名
	ListenAddrBase  string        // ローカルUDPリスンのベースアドレス (変更済み)
	PingInterval    time.Duration // キープアライブping間隔
	ReconnectDelay  time.Duration // 再接続の遅延
	MaxRetries      int           // 再接続の最大試行回数（負数は無制限）
	HandshakeExpiry time.Duration // ハンドシェイクの期限切れ時間
	// TargetPeer フィールドは削除
}

// DefaultConfig はデフォルト設定を返します
func DefaultConfig() *Config {
	return &Config{
		ServerURL:       "ws://localhost:8080/ws",
		InterfaceName:   "wg0",
		ListenAddrBase:  "", // 空文字列で自動割り当て
		PingInterval:    30 * time.Second,
		ReconnectDelay:  5 * time.Second,
		MaxRetries:      -1, // 無制限
		HandshakeExpiry: 3 * time.Minute,
	}
}

// Client はHuleguクライアントです
type Client struct {
	config    *Config
	wg        *wireguard.Manager
	conn      *websocket.Conn
	publicKey wgtypes.Key

	// 対象ピアごとのエンドポイント管理
	endpoints map[wgtypes.Key]*HuleguEndpoint

	// 有効なピアのリスト
	enabledPeers map[wgtypes.Key]bool

	sessionID string // セッションID
	packetID  uint32 // パケット識別子
	pingSeq   uint32 // pingシーケンス番号

	ctx        context.Context
	cancelFunc context.CancelFunc

	connected bool
	connMu    sync.RWMutex
	peerMu    sync.RWMutex // ピア管理用のミューテックス

	reconnectMu sync.Mutex // 再接続処理の排他制御

	// Client構造体にUDPソケットフィールドを追加
	wgConn   net.Conn   // WireGuardへの転送用UDPソケット
	wgConnMu sync.Mutex // WireGuardコネクション用ミューテックス

	// 転送用パケットのチャネル
	packetQueue chan wireguardPacket
}

// wireguardPacket は転送用パケットを表します
type wireguardPacket struct {
	data      []byte
	sourceKey wgtypes.Key
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
		packetQueue:  make(chan wireguardPacket, 100), // バッファ付きチャネル
	}

	// パケット処理ワーカーを起動
	go client.processPackets()

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
	err := c.connectToServer()
	if err != nil {
		return fmt.Errorf("server connection failed: %w", err)
	}

	// ハンドシェイクの実行
	err = c.performHandshake()
	if err != nil {
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		return fmt.Errorf("handshake failed: %w", err)
	}

	c.connected = true

	// ハンドシェイク後にWireGuardソケットを初期化
	err = c.initWireGuardConnection()
	if err != nil {
		log.Printf("Warning: Failed to initialize WireGuard connection: %v", err)
	}

	// WebSocketの読み込みループを開始
	go c.websocketReadLoop()

	// パケット転送ループを開始
	go c.packetForwardingLoop()

	log.Printf("Connected to server: %s", c.config.ServerURL)
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
			// キープアライブpingの送信
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

	// シーケンス番号の生成
	c.pingSeq++

	// Pingデータの作成
	pingData := &protocol.PingData{
		Timestamp: time.Now().UnixNano(),
		Sequence:  c.pingSeq,
	}

	// Pingデータのエンコード
	pingPayload, err := protocol.EncodePing(pingData)
	if err != nil {
		return fmt.Errorf("failed to encode ping: %w", err)
	}

	// メッセージの作成
	msg := &protocol.Message{
		Type:    protocol.TypePing,
		Payload: pingPayload,
	}

	// メッセージのエンコード
	msgBytes, err := protocol.EncodeMessage(msg)
	// WebSocketでの送信
	err = c.conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	log.Printf("Sent ping to server (seq=%d)", c.pingSeq)
	return nil
}

// reconnect はサーバーに再接続します
func (c *Client) reconnect() {
	c.reconnectMu.Lock()
	defer c.reconnectMu.Unlock()

	// すでに接続が閉じられているか確認
	c.connMu.RLock()
	if !c.connected {
		c.connMu.RUnlock()
		return
	}
	c.connMu.RUnlock()

	// 現在の接続を閉じる
	c.Disconnect()

	// 再接続を試みる
	retries := 0
	for c.config.MaxRetries < 0 || retries < c.config.MaxRetries {
		log.Printf("Attempting to reconnect (%d)...", retries+1)
		time.Sleep(c.config.ReconnectDelay)

		err := c.Connect()
		if err == nil {
			log.Printf("Successfully reconnected")
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

	switch msg.Type {
	case protocol.TypePacket:
		// パケットデータのデコード
		packet, err := protocol.DecodePacket(msg.Payload)
		if err != nil {
			log.Printf("Failed to decode packet data: %v", err)
			return
		}

		log.Printf("Received packet from server: targetKey=%s, sourceKey=%s, packetID=%d, size=%d bytes",
			packet.TargetKey.String(), packet.SourceKey.String(), packet.PacketID, len(packet.PacketData))

		// 送信元の公開鍵を使ってパケットをルーティング
		c.handleWebSocketPacket(packet.PacketData, packet.SourceKey)
	}
}

// handleWebSocketPacket はWebSocketから受信したパケットをWireGuardに転送します
func (c *Client) handleWebSocketPacket(packetData []byte, sourceKey wgtypes.Key) {
	// IPヘッダー解析（デバッグ用）
	if len(packetData) >= 20 { // 最小IPヘッダーサイズ
		version := packetData[0] >> 4
		if version == 4 { // IPv4
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
			// フォールバック: キューに入れて直接転送
			select {
			case c.packetQueue <- wireguardPacket{data: packetData, sourceKey: sourceKey}:
				log.Printf("Falling back to direct forwarding for packet from peer %s", sourceKey.String())
			default:
				log.Printf("WARNING: Packet queue full, dropping packet from %s", sourceKey)
			}
		} else {
			log.Printf("Successfully forwarded %d bytes via endpoint for peer %s", n, sourceKey.String())
		}
	} else {
		// エンドポイントが見つからない場合はキューに入れて直接転送
		select {
		case c.packetQueue <- wireguardPacket{data: packetData, sourceKey: sourceKey}:
			log.Printf("No endpoint found for peer %s, using direct forwarding", sourceKey.String())
		default:
			log.Printf("WARNING: Packet queue full, dropping packet from %s", sourceKey)
		}
	}
}

// connectToServer はWebSocketサーバーに接続します
func (c *Client) connectToServer() error {
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
	return nil
}

// performHandshake はサーバーとのハンドシェイクを実行します
func (c *Client) performHandshake() error {
	// ハンドシェイクデータの作成
	handshakeData := &protocol.HandshakeData{
		PublicKey: c.publicKey,
		Version:   protocol.ProtocolVersion,
		Timestamp: time.Now().UnixNano(),
	}

	// ハンドシェイクデータのエンコード
	handshakePayload, err := protocol.EncodeHandshake(handshakeData)
	if err != nil {
		return fmt.Errorf("failed to encode handshake: %w", err)
	}

	// メッセージの作成
	msg := &protocol.Message{
		Type:    protocol.TypeHandshake,
		Payload: handshakePayload,
	}

	// メッセージのエンコード
	msgBytes, err := protocol.EncodeMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// WebSocketでの送信
	err = c.conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	// ハンドシェイク応答の待機
	c.conn.SetReadDeadline(time.Now().Add(c.config.HandshakeExpiry))
	defer c.conn.SetReadDeadline(time.Time{}) // タイムアウトをリセット

	_, respData, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to receive handshake response: %w", err)
	}

	// メッセージのデコード
	respMsg, err := protocol.DecodeMessage(respData)
	if err != nil {
		return fmt.Errorf("failed to decode handshake response: %w", err)
	}

	// メッセージタイプの確認
	if respMsg.Type != protocol.TypeHandshakeAck {
		if respMsg.Type == protocol.TypeError {
			// エラーレスポンスの処理
			errorData, decodeErr := protocol.DecodeError(respMsg.Payload)
			if decodeErr == nil {
				return fmt.Errorf("server rejected handshake: %s (code: %d)", errorData.Message, errorData.Code)
			}
			return fmt.Errorf("server rejected handshake with unknown error")
		}
		return fmt.Errorf("unexpected response type: %d", respMsg.Type)
	}

	// ハンドシェイク応答のデコード
	ackData, err := protocol.DecodeHandshakeAck(respMsg.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode handshake ack: %w", err)
	}

	// セッションIDの保存
	c.sessionID = ackData.SessionID

	log.Printf("Handshake successful, session established: %s", c.sessionID)
	return nil
}

// Disconnect はサーバーとの接続を切断します
func (c *Client) Disconnect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if !c.connected {
		return ErrNotConnected
	}

	// 切断メッセージの送信（可能な場合）
	if c.conn != nil {
		// Disconnectメッセージの作成と送信
		msg := &protocol.Message{
			Type:    protocol.TypeDisconnect,
			Payload: []byte{},
		}

		msgBytes, err := protocol.EncodeMessage(msg)
		if err == nil {
			// エラーは無視（すでに接続が切れている可能性もある）
			c.conn.WriteMessage(websocket.BinaryMessage, msgBytes)
		}

		// WebSocketのクローズメッセージ送信
		c.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

		// 接続のクローズ
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
	// コンテキストのキャンセル
	c.cancelFunc()

	// 接続のクローズ
	if c.connected {
		c.Disconnect()
	}

	// すべてのピアを無効化
	c.peerMu.Lock()
	for peerKey, endpoint := range c.endpoints {
		if endpoint != nil {
			endpoint.Close()
		}
		delete(c.endpoints, peerKey)
	}
	c.enabledPeers = make(map[wgtypes.Key]bool)
	c.peerMu.Unlock()

	// WireGuardマネージャーのクローズ
	if c.wg != nil {
		c.wg.Close()
	}

	// WireGuardコネクションのクローズ
	c.wgConnMu.Lock()
	if c.wgConn != nil {
		c.wgConn.Close()
		c.wgConn = nil
	}
	c.wgConnMu.Unlock()

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

			// 現在のエンドポイントのスナップショットを取得
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
				// 非ブロッキングでチェック（ゴルーチンでは不要かも）
				packet, err := endpoint.ReadPacket()
				if err != nil {
					// タイムアウトは無視
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					log.Printf("Failed to read packet from peer %s: %v", peerKey, err)
					continue
				}

				// WireGuardからのパケットの場合のみ転送
				if endpoint.IsFromWireGuard(packet) {
					// パケットをWebSocketサーバーに転送（ピア情報付き）
					err := c.forwardPacketToServer(packet.Data, peerKey)
					if err != nil {
						log.Printf("Failed to forward packet to server for peer %s: %v", peerKey, err)
					}
				}
			}

			// CPU負荷軽減のため短時間スリープ
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

	// 送信先ログの追加
	log.Printf("Forwarding packet to server for peer %s, packetID=%d, size=%d bytes",
		peerKey.String(), c.packetID, len(packetData))

	// パケットデータの作成（宛先ピア情報を含む）
	packet := &protocol.PacketData{
		TargetKey:  peerKey,     // 宛先ピアの公開鍵
		SourceKey:  c.publicKey, // 送信元（自分自身）の公開鍵 - 新規追加
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

// IsConnected はクライアントが接続されているかを返します
func (c *Client) IsConnected() bool {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.connected
}

// GetSessionID は現在のセッションIDを返します
func (c *Client) GetSessionID() string {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.sessionID
}

// GetTargetPeer は対象ピアの公開鍵を返します
func (c *Client) GetTargetPeer() (wgtypes.Key, error) {
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()

	if len(c.enabledPeers) == 0 {
		return wgtypes.Key{}, fmt.Errorf("no enabled peers")
	}

	// 最初の有効なピアを返す（互換性のため）
	for key := range c.enabledPeers {
		return key, nil
	}

	// コンパイラが到達できないことを知らないため必要
	return wgtypes.Key{}, fmt.Errorf("unexpected error")
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
		log.Printf("Closed endpoint for peer %s", peerKeyStr)
	}

	// 有効なピアリストから削除
	delete(c.enabledPeers, peerKey)

	log.Printf("Peer %s disabled for Hulegu", peerKeyStr)
	return nil
}

// GetEnabledPeers は有効化されているピアのリストを返します
func (c *Client) GetEnabledPeers() []wgtypes.Key {
	c.peerMu.RLock()
	defer c.peerMu.RUnlock()

	peers := make([]wgtypes.Key, 0, len(c.enabledPeers))
	for key := range c.enabledPeers {
		peers = append(peers, key)
	}
	return peers
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
		// デフォルトは別のポートで127.0.0.1にバインド
		listenAddr = "127.0.0.1:0" // OSに空きポートを割り当ててもらう
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

	// ここで対象ピアのエンドポイントを更新
	err = c.wg.UpdatePeerEndpoint(peerKey, localAddr)
	if err != nil {
		// エンドポイントをクローズして戻す
		endpoint.Close()
		delete(c.endpoints, peerKey)
		return fmt.Errorf("failed to update WireGuard peer endpoint: %w", err)
	}

	log.Printf("Updated WireGuard peer %s endpoint to %s", peerKey, localAddr.String())
	return nil
}

// StartPacketForwarding はパケット転送ループを開始します
func (c *Client) StartPacketForwarding() {
	// すでに実行中のパケット転送ループがある場合は重複して起動しないよう制御が必要
	go c.packetForwardingLoop()
}

// 対象ピアが有効化されているか確認する関数を追加
func (c *Client) IsPeerEnabled(peerKeyStr string) (bool, error) {
	peerKey, err := wgtypes.ParseKey(peerKeyStr)
	if err != nil {
		return false, fmt.Errorf("invalid peer key: %w", err)
	}

	c.peerMu.RLock()
	defer c.peerMu.RUnlock()

	// ピアが有効化されているか確認
	enabled, exists := c.enabledPeers[peerKey]
	return exists && enabled, nil
}

// WireGuardソケット初期化関数
func (c *Client) initWireGuardConnection() error {
	port := c.wg.GetListenPort()
	if port == 0 {
		return fmt.Errorf("WireGuard not listening on any port")
	}

	wgAddr := fmt.Sprintf("127.0.0.1:%d", port)

	c.wgConnMu.Lock()
	defer c.wgConnMu.Unlock()

	// 既存のコネクションがあればクローズ
	if c.wgConn != nil {
		c.wgConn.Close()
	}

	// 新しいUDPソケットを作成
	conn, err := net.Dial("udp", wgAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to WireGuard: %w", err)
	}

	c.wgConn = conn
	log.Printf("Initialized WireGuard connection to %s", wgAddr)
	return nil
}

// パケット処理ワーカー
func (c *Client) processPackets() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case packet := <-c.packetQueue:
			// 実際のWireGuard転送処理
			c.forwardPacketToWireGuard(packet.data)
		}
	}
}

// 転送処理の実装
func (c *Client) forwardPacketToWireGuard(packetData []byte) {
	// WireGuardのリッスンポートを取得
	port := c.wg.GetListenPort()
	if port == 0 {
		log.Printf("ERROR: WireGuard not listening on any port")
		return
	}

	// WireGuardのリッスンアドレス
	wgAddr := fmt.Sprintf("127.0.0.1:%d", port)

	// UDPアドレスの解決
	addr, err := net.ResolveUDPAddr("udp", wgAddr)
	if err != nil {
		log.Printf("ERROR: Failed to resolve WireGuard address: %v", err)
		return
	}

	// UDPコネクション作成
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		log.Printf("ERROR: Failed to connect to WireGuard: %v", err)
		return
	}
	defer conn.Close()

	// パケットを転送
	n, err := conn.Write(packetData)
	if err != nil {
		log.Printf("ERROR: Failed to forward packet to WireGuard: %v", err)
	} else {
		log.Printf("Successfully forwarded %d bytes to WireGuard at %s", n, wgAddr)
	}
}
