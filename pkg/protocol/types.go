package protocol

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Message はHuleguプロトコルのメッセージを表します
type Message struct {
	Type    MessageType // メッセージタイプ
	Payload []byte      // ペイロードデータ
}

// HandshakeData は初期ハンドシェイク情報を含みます
type HandshakeData struct {
	PublicKey wgtypes.Key // クライアントの公開鍵
	Version   uint16      // プロトコルバージョン
	Timestamp int64       // タイムスタンプ（リプレイ攻撃対策）
}

// HandshakeAckData はハンドシェイク応答情報を含みます
type HandshakeAckData struct {
	SessionID  string // 確立されたセッションID
	ServerTime int64  // サーバーの現在時刻
	Expiry     int64  // セッション有効期限
}

// PingData はキープアライブデータを含みます
type PingData struct {
	Timestamp int64  // 送信時刻
	Sequence  uint32 // シーケンス番号
}

// PongData はPingへの応答データを含みます
type PongData struct {
	EchoTimestamp int64  // 元のPingのタイムスタンプ
	ServerTime    int64  // サーバー時刻
	Sequence      uint32 // 対応するPingのシーケンス番号
}

// PacketData はWireGuardパケットを含みます
type PacketData struct {
	TargetKey  wgtypes.Key // 宛先ピアの公開鍵（サーバーが使用）
	PacketID   uint32      // パケット識別子（重複検出用）
	PacketData []byte      // 実際のWireGuardパケットデータ
}

// ErrorData はエラー情報を含みます
type ErrorData struct {
	Code    uint16 // エラーコード
	Message string // エラーメッセージ
}

// エラーコード定義
const (
	ErrorUnknown          uint16 = 0x0000 // 不明なエラー
	ErrorInvalidMessage   uint16 = 0x0001 // 無効なメッセージ形式
	ErrorAuthFailure      uint16 = 0x0002 // 認証失敗
	ErrorSessionExpired   uint16 = 0x0003 // セッション期限切れ
	ErrorRateLimited      uint16 = 0x0004 // レート制限超過
	ErrorPeerNotFound     uint16 = 0x0005 // 指定されたピアが見つからない
	ErrorServerOverloaded uint16 = 0x0006 // サーバー過負荷
	ErrorProtocolVersion  uint16 = 0x0007 // 互換性のないプロトコルバージョン
)
