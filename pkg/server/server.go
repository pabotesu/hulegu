package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pabotesu/hulegu/pkg/protocol"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config はHuleguサーバーの設定です
type Config struct {
	ListenAddr      string        // WebSocketリスニングアドレス（例: ":8080"）
	Path            string        // WebSocketのパス（例: "/ws"）
	SessionTimeout  time.Duration // セッションのタイムアウト時間
	MaxConnections  int           // 最大接続数（0は無制限）
	TLSCertFile     string        // TLS証明書ファイル（空なら非TLS）
	TLSKeyFile      string        // TLS秘密鍵ファイル
	AllowedPeers    []string      // 許可するピアの公開鍵（空なら制限なし）
	PingInterval    time.Duration // Pingの送信間隔
	PongTimeout     time.Duration // Pongの待機タイムアウト
	ReadBufferSize  int           // WebSocketの読み取りバッファサイズ
	WriteBufferSize int           // WebSocketの書き込みバッファサイズ
	LogLevel        string        // ログレベル（debug, info, warn, error）
}

// DefaultConfig はデフォルトのサーバー設定を返します
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:      ":8080",
		Path:            "/ws",
		SessionTimeout:  24 * time.Hour,
		MaxConnections:  0,
		PingInterval:    30 * time.Second,
		PongTimeout:     10 * time.Second,
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		LogLevel:        "info",
	}
}

// Server はHuleguサーバーの実装です
type Server struct {
	config               *Config
	upgrader             websocket.Upgrader
	server               *http.Server
	ctx                  context.Context
	cancelFunc           context.CancelFunc
	connections          map[string]*Connection      // セッションID -> 接続
	connectionsByPeerKey map[wgtypes.Key]*Connection // ピア公開鍵 -> 接続
	sessions             map[string]*Session         // セッションID -> セッション
	connectionsMu        sync.RWMutex                // 接続用ミューテックス
	sessionsMu           sync.RWMutex
	stats                ServerStats
	statsMu              sync.RWMutex
}

// ServerStats はサーバーの統計情報です
type ServerStats struct {
	ClientsConnected    int       // 接続中のクライアント数
	SessionsActive      int       // アクティブなセッション数
	PacketsForwarded    uint64    // 転送されたパケット数
	BytesForwarded      uint64    // 転送されたバイト数
	ConnectionsRejected uint64    // 拒否された接続数
	HandshakesCompleted uint64    // 完了したハンドシェイク数
	HandshakesFailed    uint64    // 失敗したハンドシェイク数
	StartTime           time.Time // サーバー起動時間
	LastSessionCleanup  time.Time // 最後のセッションクリーンアップ時間
}

// New は新しいHuleguサーバーを作成します
func New(config *Config) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// コンテキストの作成
	ctx, cancel := context.WithCancel(context.Background())

	// WebSocketアップグレーダーの設定
	upgrader := websocket.Upgrader{
		ReadBufferSize:  config.ReadBufferSize,
		WriteBufferSize: config.WriteBufferSize,
		// クロスオリジン要求を許可（必要に応じて制限可）
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	server := &Server{
		config:               config,
		upgrader:             upgrader,
		ctx:                  ctx,
		cancelFunc:           cancel,
		connections:          make(map[string]*Connection),
		connectionsByPeerKey: make(map[wgtypes.Key]*Connection),
		sessions:             make(map[string]*Session),
		stats: ServerStats{
			StartTime: time.Now(),
		},
	}

	return server, nil
}

// Start はサーバーを起動します
func (s *Server) Start() error {
	// HTTPサーバーの設定
	mux := http.NewServeMux()
	mux.HandleFunc(s.config.Path, s.handleWebSocket)

	s.server = &http.Server{
		Addr:    s.config.ListenAddr,
		Handler: mux,
	}

	// セッションクリーンアップゴルーチンの開始
	go s.sessionCleanupLoop()

	// HTTPSサーバーの起動
	if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
		log.Printf("Starting HTTPS server on %s", s.config.ListenAddr)
		return s.server.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
	}

	// HTTPサーバーの起動
	log.Printf("Starting HTTP server on %s", s.config.ListenAddr)
	return s.server.ListenAndServe()
}

// Stop はサーバーを停止します
func (s *Server) Stop() error {
	s.cancelFunc() // コンテキストのキャンセル

	// すべての接続を閉じる
	s.connectionsMu.Lock()
	for _, conn := range s.connections {
		conn.Close()
	}
	s.connectionsMu.Unlock()

	// HTTPサーバーの停止
	if s.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(shutdownCtx)
	}

	return nil
}

// handleWebSocket はWebSocket接続リクエストを処理します
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// 最大接続数のチェック
	if s.config.MaxConnections > 0 {
		s.connectionsMu.RLock()
		if len(s.connections) >= s.config.MaxConnections {
			s.connectionsMu.RUnlock()
			http.Error(w, "Maximum connections reached", http.StatusServiceUnavailable)
			s.statsMu.Lock()
			s.stats.ConnectionsRejected++
			s.statsMu.Unlock()
			return
		}
		s.connectionsMu.RUnlock()
	}

	// WebSocketへのアップグレード
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Failed to upgrade to WebSocket: %v", err)
		s.statsMu.Lock()
		s.stats.ConnectionsRejected++
		s.statsMu.Unlock()
		return
	}

	// 接続の処理
	s.handleConnection(conn)
}

// handleConnection は新しいWebSocket接続を処理します
func (s *Server) handleConnection(conn *websocket.Conn) {
	// 初期接続作成（認証前）
	connection := NewConnection(conn)
	defer connection.Close()

	// ハンドシェイク処理
	err := s.performHandshake(connection)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		s.sendError(connection, fmt.Sprintf("Authentication failed: %v", err))
		s.statsMu.Lock()
		s.stats.HandshakesFailed++
		s.statsMu.Unlock()
		return
	}

	// ハンドシェイク成功後の処理
	s.statsMu.Lock()
	s.stats.HandshakesCompleted++
	s.stats.ClientsConnected++
	s.statsMu.Unlock()

	// メインメッセージループ
	s.messageLoop(connection)

	// 接続終了時の処理
	s.removeConnection(connection)
	s.statsMu.Lock()
	s.stats.ClientsConnected--
	s.statsMu.Unlock()
}

// performHandshake はクライアントとのハンドシェイクを処理します
func (s *Server) performHandshake(connection *Connection) error {
	// ハンドシェイクメッセージの待機
	_, message, err := connection.Conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("failed to read handshake message: %w", err)
	}

	// メッセージのデコード
	msg, err := protocol.DecodeMessage(message)
	if err != nil {
		return fmt.Errorf("failed to decode handshake message: %w", err)
	}

	// ハンドシェイクメッセージのチェック
	if msg.Type != protocol.TypeHandshake {
		return fmt.Errorf("expected handshake message, got type %d", msg.Type)
	}

	// ハンドシェイクデータのデコード
	handshakeData, err := protocol.DecodeHandshake(msg.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode handshake data: %w", err)
	}
	// ゼロ値比較を使用
	if handshakeData.PublicKey == (wgtypes.Key{}) {
		return fmt.Errorf("invalid public key (zero key)")
	}
	// 許可リストのチェック (オプション)
	if len(s.config.AllowedPeers) > 0 {
		clientKey := handshakeData.PublicKey.String()
		allowed := false
		for _, key := range s.config.AllowedPeers {
			if key == clientKey {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("client with key %s not in allowed list", clientKey)
		}
	}

	// 接続情報の設定
	connection.PublicKey = handshakeData.PublicKey
	connection.ConnectedAt = time.Now()
	connection.LastActivity = time.Now()

	// セッション作成
	session, err := s.createSession(connection.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	connection.SessionID = session.ID

	// 接続マップに追加
	s.connectionsMu.Lock()
	s.connections[connection.SessionID] = connection
	s.connectionsByPeerKey[connection.PublicKey] = connection
	s.connectionsMu.Unlock()

	// ハンドシェイク応答の送信
	ackData := &protocol.HandshakeAckData{
		SessionID:  session.ID,
		ServerTime: time.Now().UnixNano(),
		Expiry:     session.ExpiresAt.UnixNano(),
	}

	// ハンドシェイク応答のエンコード
	ackPayload, err := protocol.EncodeHandshakeAck(ackData)
	if err != nil {
		return fmt.Errorf("failed to encode handshake ack: %w", err)
	}

	// メッセージの作成
	respMsg := &protocol.Message{
		Type:    protocol.TypeHandshakeAck,
		Payload: ackPayload,
	}

	// メッセージのエンコード
	respBytes, err := protocol.EncodeMessage(respMsg)
	if err != nil {
		return fmt.Errorf("failed to encode handshake response: %w", err)
	}

	// 応答の送信
	err = connection.Conn.WriteMessage(websocket.BinaryMessage, respBytes)
	if err != nil {
		return fmt.Errorf("failed to send handshake response: %w", err)
	}

	log.Printf("Client %s authenticated with session %s", connection.PublicKey, connection.SessionID)
	return nil
}

// sendError はエラーメッセージをクライアントに送信します
func (s *Server) sendError(connection *Connection, errorMessage string) {
	// シンプルなバイナリメッセージとして送信
	msg := map[string]interface{}{
		"error":     true,
		"message":   errorMessage,
		"timestamp": time.Now().UnixNano(),
	}

	// JSONエンコード
	jsonData, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to encode error message: %v", err)
		return
	}

	// エラーメッセージの送信
	err = connection.Conn.WriteMessage(websocket.TextMessage, jsonData)
	if err != nil {
		log.Printf("Failed to send error message: %v", err)
	}
}

// messageLoop はクライアントからのメッセージを処理するメインループです
func (s *Server) messageLoop(connection *Connection) {
	// Pingタイマーの設定
	pingTicker := time.NewTicker(s.config.PingInterval)
	defer pingTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			// サーバーのシャットダウン
			return
		case <-pingTicker.C:
			// Pingの送信
			err := s.sendPing(connection)
			if err != nil {
				log.Printf("Failed to send ping to connection %s: %v", connection.SessionID, err)
				return
			}
		default:
			// 接続からのメッセージ読み取り
			_, message, err := connection.Conn.ReadMessage()
			if err != nil {
				log.Printf("Read error from connection %s: %v", connection.SessionID, err)
				return
			}

			// メッセージの処理
			err = s.handleMessage(connection, message)
			if err != nil {
				log.Printf("Error handling message from connection %s: %v", connection.SessionID, err)
				s.sendError(connection, fmt.Sprintf("Invalid message: %v", err))

				// 深刻なエラーの場合は接続を閉じる
				if _, ok := err.(*FatalError); ok {
					return
				}
			}
		}
	}
}

// FatalError は致命的なエラーを表します
type FatalError struct {
	Err error
}

func (e *FatalError) Error() string {
	return e.Err.Error()
}

// createSession は新しいセッションを作成します
func (s *Server) createSession(clientKey wgtypes.Key) (*Session, error) {
	// 既存のセッションがあるか確認
	s.sessionsMu.RLock()
	for _, session := range s.sessions {
		if session.ClientKey == clientKey {
			// 既存のセッションを更新
			session.LastRenewed = time.Now()
			session.ExpiresAt = time.Now().Add(s.config.SessionTimeout)
			s.sessionsMu.RUnlock()
			return session, nil
		}
	}
	s.sessionsMu.RUnlock()

	// 新しいセッションの作成
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	session := &Session{
		ID:          sessionID,
		ClientKey:   clientKey,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(s.config.SessionTimeout),
		LastRenewed: time.Now(),
	}

	// セッションをマップに追加
	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	s.statsMu.Lock()
	s.stats.SessionsActive++
	s.statsMu.Unlock()

	return session, nil
}

// removeConnection はクライアントとそのセッションを削除します
func (s *Server) removeConnection(connection *Connection) {
	s.connectionsMu.Lock()
	delete(s.connections, connection.SessionID)
	delete(s.connectionsByPeerKey, connection.PublicKey)
	s.connectionsMu.Unlock()

	// セッションは別のクリーンアップ処理で処理
}

// sessionCleanupLoop は期限切れのセッションをクリーンアップします
func (s *Server) sessionCleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupExpiredSessions()
		}
	}
}

// cleanupExpiredSessions は期限切れのセッションを削除します
func (s *Server) cleanupExpiredSessions() {
	now := time.Now()
	expiredSessions := make([]string, 0)

	// 期限切れのセッションを検索
	s.sessionsMu.RLock()
	for id, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, id)
		}
	}
	s.sessionsMu.RUnlock()

	// 期限切れのセッションを削除
	for _, id := range expiredSessions {
		s.sessionsMu.Lock()
		delete(s.sessions, id)
		s.sessionsMu.Unlock()

		log.Printf("Session %s expired and removed", id)
	}

	if len(expiredSessions) > 0 {
		s.statsMu.Lock()
		s.stats.SessionsActive -= len(expiredSessions)
		if s.stats.SessionsActive < 0 {
			s.stats.SessionsActive = 0
		}
		s.stats.LastSessionCleanup = now
		s.statsMu.Unlock()
	}
}

// sendPing はクライアントにPingを送信します
func (s *Server) sendPing(connection *Connection) error {
	// Pingデータの作成
	pingData := &protocol.PingData{
		Timestamp: time.Now().UnixNano(),
		Sequence:  connection.NextPingSeq(),
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
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// Pingの送信
	connection.mu.Lock()
	defer connection.mu.Unlock()

	err = connection.Conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	connection.Stats.LastPingSent = time.Now()
	return nil
}

// handleMessage はクライアントから受信したメッセージを処理します
func (s *Server) handleMessage(connection *Connection, data []byte) error {
	// メッセージのデコード
	msg, err := protocol.DecodeMessage(data)
	if err != nil {
		return fmt.Errorf("failed to decode message: %w", err)
	}

	// メッセージタイプに基づく処理
	switch msg.Type {
	case protocol.TypePing:
		return s.handlePing(connection, msg.Payload)
	case protocol.TypePong:
		return s.handlePong(connection, msg.Payload)
	case protocol.TypePacket:
		return s.handlePacket(connection, msg.Payload)
	case protocol.TypeDisconnect:
		log.Printf("Client %s requested disconnect", connection.SessionID)
		return &FatalError{Err: fmt.Errorf("client requested disconnect")}
	default:
		return fmt.Errorf("unknown message type: %d", msg.Type)
	}
}

// handlePing はクライアントからのPingを処理します
func (s *Server) handlePing(connection *Connection, payload []byte) error {
	// Pingデータのデコード
	pingData, err := protocol.DecodePing(payload)
	if err != nil {
		return fmt.Errorf("failed to decode ping: %w", err)
	}

	// 接続の最終アクティビティを更新
	connection.mu.Lock()
	connection.LastActivity = time.Now()
	connection.mu.Unlock()

	// Pongデータの作成
	pongData := &protocol.PongData{
		EchoTimestamp: pingData.Timestamp,
		ServerTime:    time.Now().UnixNano(),
		Sequence:      pingData.Sequence,
	}

	// Pongデータのエンコード
	pongPayload, err := protocol.EncodePong(pongData)
	if err != nil {
		return fmt.Errorf("failed to encode pong: %w", err)
	}

	// メッセージの作成
	msg := &protocol.Message{
		Type:    protocol.TypePong,
		Payload: pongPayload,
	}

	// メッセージのエンコード
	msgBytes, err := protocol.EncodeMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to encode message: %w", err)
	}

	// Pongの送信
	connection.mu.Lock()
	defer connection.mu.Unlock()

	err = connection.Conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send pong: %w", err)
	}

	return nil
}

// handlePong はクライアントからのPongを処理します
func (s *Server) handlePong(connection *Connection, payload []byte) error {
	// Pongデータのデコード
	pongData, err := protocol.DecodePong(payload)
	if err != nil {
		return fmt.Errorf("failed to decode pong: %w", err)
	}

	// 接続の最終アクティビティを更新
	connection.mu.Lock()
	connection.LastActivity = time.Now()
	connection.Stats.LastPongReceived = time.Now()

	// レイテンシーの計算
	if pongData.EchoTimestamp > 0 {
		rtt := time.Now().UnixNano() - pongData.EchoTimestamp
		connection.Stats.Latency = time.Duration(rtt)
	}
	connection.mu.Unlock()

	return nil
}

// handlePacket はクライアントからのパケットを処理します
func (s *Server) handlePacket(connection *Connection, payload []byte) error {
	// パケットデータのデコード
	packet, err := protocol.DecodePacket(payload)
	if err != nil {
		return fmt.Errorf("failed to decode packet: %w", err)
	}

	log.Printf("[DEBUG] Received packet from client %s, targetKey=%s",
		connection.PublicKey.String(), packet.TargetKey.String())

	// 宛先接続の検索
	s.connectionsMu.RLock()
	targetConnection, exists := s.connectionsByPeerKey[packet.TargetKey]
	s.connectionsMu.RUnlock()

	if !exists || targetConnection == nil {
		log.Printf("[ERROR] No connection found for target key: %s", packet.TargetKey)
		return fmt.Errorf("no connection found for target key: %s", packet.TargetKey)
	}

	log.Printf("[DEBUG] Found target connection for key %s", packet.TargetKey.String())

	// パケットの送信元情報を維持し、SourceKeyに設定
	modifiedPacket := &protocol.PacketData{
		TargetKey:  packet.TargetKey,     // 元の宛先キーを維持
		SourceKey:  connection.PublicKey, // 送信元の公開鍵を明示的に設定
		PacketID:   packet.PacketID,      // 元のパケットIDを維持
		PacketData: packet.PacketData,    // パケットデータは変更なし
	}

	// 修正: より明確なログ出力に変更
	log.Printf("[DEBUG] Forwarding packet: target=%s, source=%s, packetID=%d, size=%d bytes",
		packet.TargetKey.String(), connection.PublicKey.String(), packet.PacketID, len(packet.PacketData))

	// 変更したパケットをエンコード
	packetPayload, err := protocol.EncodePacket(modifiedPacket)
	if err != nil {
		return fmt.Errorf("failed to encode modified packet: %w", err)
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

	// 宛先接続に送信
	targetConnection.mu.Lock()
	defer targetConnection.mu.Unlock()

	if targetConnection.Conn == nil {
		return fmt.Errorf("target connection is nil")
	}

	err = targetConnection.Conn.WriteMessage(websocket.BinaryMessage, msgBytes)
	if err != nil {
		return fmt.Errorf("failed to send packet to target connection: %w", err)
	}

	// 統計情報の更新
	connection.Stats.PacketsOut++
	connection.Stats.BytesOut += uint64(len(packet.PacketData))
	targetConnection.Stats.PacketsIn++
	targetConnection.Stats.BytesIn += uint64(len(packet.PacketData))

	s.statsMu.Lock()
	s.stats.PacketsForwarded++
	s.stats.BytesForwarded += uint64(len(packet.PacketData))
	s.statsMu.Unlock()

	log.Printf("[DEBUG] Packet forwarded: from %s to %s, size=%d bytes",
		connection.PublicKey.String(), packet.TargetKey.String(), len(packet.PacketData))

	return nil
}

// GetStats はサーバーの統計情報を返します
func (s *Server) GetStats() ServerStats {
	s.statsMu.RLock()
	defer s.statsMu.RUnlock()
	return s.stats
}

// GetConnectionStats はクライアントの統計情報を返します
func (s *Server) GetConnectionStats(sessionID string) (ConnectionStats, error) {
	s.connectionsMu.RLock()
	connection, exists := s.connections[sessionID]
	s.connectionsMu.RUnlock()

	if !exists || connection == nil {
		return ConnectionStats{}, fmt.Errorf("connection not found: %s", sessionID)
	}

	connection.mu.RLock()
	defer connection.mu.RUnlock()
	return connection.Stats, nil
}

// GetClientStats は後方互換性のために維持（非推奨）
func (s *Server) GetClientStats(sessionID string) (ConnectionStats, error) {
	return s.GetConnectionStats(sessionID)
}

// GetAllConnectionStats はすべての接続の統計情報を返します
func (s *Server) GetAllConnectionStats() []ConnectionStats {
	s.connectionsMu.RLock()
	defer s.connectionsMu.RUnlock()

	stats := make([]ConnectionStats, 0, len(s.connections))
	for _, conn := range s.connections {
		conn.mu.RLock()
		stats = append(stats, conn.Stats)
		conn.mu.RUnlock()
	}

	return stats
}
