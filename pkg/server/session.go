package server

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Session はクライアントのセッションを表します
type Session struct {
	ID          string      // セッションID
	ClientKey   wgtypes.Key // クライアントの公開鍵
	CreatedAt   time.Time   // 作成時刻
	ExpiresAt   time.Time   // 有効期限
	LastRenewed time.Time   // 最終更新時刻
}

// generateSessionID はランダムなセッションIDを生成します
func generateSessionID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
