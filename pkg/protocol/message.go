package protocol

// MessageType はHuleguプロトコルのメッセージタイプを定義します
type MessageType byte

const (
	// コントロールメッセージ
	TypeHandshake    MessageType = 0x01 // 初期ハンドシェイク
	TypeHandshakeAck MessageType = 0x02 // ハンドシェイク応答
	TypePing         MessageType = 0x03 // キープアライブpingリクエスト
	TypePong         MessageType = 0x04 // pingレスポンス
	TypeDisconnect   MessageType = 0x05 // 正常切断通知

	// データメッセージ
	TypePacket    MessageType = 0x10 // WireGuardパケット
	TypePacketAck MessageType = 0x11 // パケット受信確認（オプション）

	// エラーメッセージ
	TypeError MessageType = 0xF0 // エラー通知
)
