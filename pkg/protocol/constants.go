package protocol

import "time"

const (
	// ProtocolVersion は現在のプロトコルバージョンを定義します
	ProtocolVersion uint16 = 1

	// MaxMessageSize はメッセージの最大サイズを定義します
	MaxMessageSize = 65535

	// MaxPayloadSize はペイロードの最大サイズを定義します
	MaxPayloadSize = MaxMessageSize - 3

	// HandshakeTimeout はハンドシェイクのタイムアウト時間です
	HandshakeTimeout = 10 * time.Second

	// MaxTimestampDrift はタイムスタンプの許容ずれ時間です
	MaxTimestampDrift = 30 * time.Second

	// DefaultSessionExpiry はデフォルトのセッション有効期限です
	DefaultSessionExpiry = 24 * time.Hour
)
