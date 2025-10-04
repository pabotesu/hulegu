package server

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Connection はサーバーに接続したクライアントを表します
type Connection struct {
	PublicKey    wgtypes.Key     // クライアントの公開鍵
	SessionID    string          // セッションID
	Conn         *websocket.Conn // WebSocket接続
	ConnectedAt  time.Time       // 接続時刻
	LastActivity time.Time       // 最後のアクティビティ時刻
	Stats        ConnectionStats // 統計情報
	pingSeq      uint32          // Pingシーケンス番号
	mu           sync.RWMutex    // 同期用ミューテックス
}

// ConnectionStats はクライアントの統計情報を表します
type ConnectionStats struct {
	PacketsIn        uint64        // 受信パケット数
	PacketsOut       uint64        // 送信パケット数
	BytesIn          uint64        // 受信バイト数
	BytesOut         uint64        // 送信バイト数
	LastPingSent     time.Time     // 最後にPingを送信した時刻
	LastPongReceived time.Time     // 最後にPongを受信した時刻
	Latency          time.Duration // 推定レイテンシ
}

// NewConnection は新しいクライアントを作成します
func NewConnection(conn *websocket.Conn) *Connection {
	now := time.Now()
	return &Connection{
		Conn:         conn,
		ConnectedAt:  now,
		LastActivity: now,
		Stats:        ConnectionStats{},
	}
}

// Close はクライアントの接続を閉じます
func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Conn != nil {
		c.Conn.Close()
		c.Conn = nil
	}
}

// NextPingSeq は次のPingシーケンス番号を返します
func (c *Connection) NextPingSeq() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pingSeq++
	return c.pingSeq
}
