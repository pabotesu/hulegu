package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// GenerateSessionID は新しいセッションIDを生成します
func GenerateSessionID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GetCurrentTimestamp は現在のUNIXタイムスタンプを返します
func GetCurrentTimestamp() int64 {
	return time.Now().UnixNano()
}

// IsTimestampValid はタイムスタンプが有効期間内かどうかを確認します
func IsTimestampValid(timestamp int64, maxDrift time.Duration) bool {
	now := time.Now().UnixNano()
	drift := now - timestamp
	return drift >= 0 && drift <= maxDrift.Nanoseconds()
}

// NextPacketID は次のパケットIDを生成します
func NextPacketID(currentID uint32) uint32 {
	return currentID + 1
}
