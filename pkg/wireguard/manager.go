package wireguard

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// エラー定義
var (
	ErrDeviceNotFound   = errors.New("wireguard: device not found")
	ErrPeerNotFound     = errors.New("wireguard: peer not found")
	ErrInvalidPublicKey = errors.New("wireguard: invalid public key")
)

// Manager はWireGuardインターフェースを管理する
type Manager struct {
	client        *wgctrl.Client
	interfaceName string
	device        *wgtypes.Device
}

// New は新しいWireGuardマネージャーを作成する
func New(interfaceName string) (*Manager, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl initialization error: %w", err)
	}

	wg := &Manager{
		client:        client,
		interfaceName: interfaceName,
	}

	err = wg.RefreshDeviceInfo()
	if err != nil {
		client.Close()
		return nil, err
	}

	log.Printf("Initialized WireGuard device %s", interfaceName)
	return wg, nil
}

// Close はリソースを解放する
func (w *Manager) Close() error {
	if w.client != nil {
		return w.client.Close()
	}
	return nil
}

// RefreshDeviceInfo は最新のデバイス情報を取得する
func (w *Manager) RefreshDeviceInfo() error {
	device, err := w.client.Device(w.interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface '%s': %w", w.interfaceName, err)
	}
	w.device = device
	return nil
}

// GetPublicKey はデバイスの公開鍵を返す
func (w *Manager) GetPublicKey() wgtypes.Key {
	if w.device == nil {
		return wgtypes.Key{}
	}
	return w.device.PublicKey
}

// GetListenPort はWireGuardインターフェースのリスニングポートを取得します
func (m *Manager) GetListenPort() int {
	// 最新のデバイス情報を取得
	err := m.RefreshDeviceInfo()
	if err != nil {
		log.Printf("Failed to refresh device info: %v", err)
		return 0
	}

	// デバイスがリスニングしているポートを返す
	if m.device != nil {
		return m.device.ListenPort
	}

	return 0
}

// GetPeers は登録済みのピア一覧を返す
func (w *Manager) GetPeers() []wgtypes.Peer {
	if w.device == nil {
		return nil
	}
	return w.device.Peers
}

// GetPeerByPublicKey は公開鍵でピアを検索する
func (w *Manager) GetPeerByPublicKey(pubKey wgtypes.Key) (*wgtypes.Peer, error) {
	if w.device == nil {
		return nil, ErrDeviceNotFound
	}

	for _, peer := range w.device.Peers {
		if peer.PublicKey == pubKey {
			return &peer, nil
		}
	}

	return nil, ErrPeerNotFound
}

// UpdatePeerEndpoint はピアのエンドポイントを更新する
func (w *Manager) UpdatePeerEndpoint(pubKey wgtypes.Key, endpoint *net.UDPAddr) error {
	// 既存のピア設定を取得
	if _, err := w.GetPeerByPublicKey(pubKey); err != nil {
		return fmt.Errorf("cannot update endpoint: %w", err)
	}

	// 既存の設定を保持しながらエンドポイントのみ更新
	peerConfig := wgtypes.PeerConfig{
		PublicKey:         pubKey,
		UpdateOnly:        true, // 既存のピアのみ更新
		Endpoint:          endpoint,
		ReplaceAllowedIPs: false, // 既存のAllowedIPsを保持
	}

	config := wgtypes.Config{
		Peers: []wgtypes.PeerConfig{peerConfig},
	}

	err := w.client.ConfigureDevice(w.interfaceName, config)
	if err != nil {
		return fmt.Errorf("failed to update peer endpoint: %w", err)
	}

	// 設定後にデバイス情報を更新
	return w.RefreshDeviceInfo()
}

// IsPeerActive はピアがアクティブかどうかを判断する
func (w *Manager) IsPeerActive(pubKey wgtypes.Key, timeout time.Duration) (bool, error) {
	peer, err := w.GetPeerByPublicKey(pubKey)
	if err != nil {
		return false, err
	}

	// 最後のハンドシェイクからの経過時間をチェック
	if peer.LastHandshakeTime.IsZero() {
		return false, nil // ハンドシェイクなし
	}

	elapsed := time.Since(peer.LastHandshakeTime)
	return elapsed < timeout, nil
}

// GetPeerStats はピアの統計情報を取得する
func (w *Manager) GetPeerStats(pubKey wgtypes.Key) (rx uint64, tx uint64, lastHandshake time.Time, err error) {
	peer, err := w.GetPeerByPublicKey(pubKey)
	if err != nil {
		return 0, 0, time.Time{}, err
	}

	return uint64(peer.ReceiveBytes), uint64(peer.TransmitBytes), peer.LastHandshakeTime, nil
}

// WatchPeers は定期的にピア情報を監視し、停止用の関数を返す
func (w *Manager) WatchPeers(interval time.Duration, callback func([]wgtypes.Peer, error)) (stop func()) {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				var peers []wgtypes.Peer
				err := w.RefreshDeviceInfo()
				if err == nil {
					peers = w.GetPeers()
				}
				// エラーも含めてコールバックに通知
				callback(peers, err)
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	// 監視を停止するための関数を返す
	return func() {
		close(done)
	}
}

// PrintDeviceInfo はデバイス情報を出力する（デバッグ用）
func (w *Manager) PrintDeviceInfo() {
	if w.device == nil {
		log.Println("No device information available")
		return
	}

	log.Printf("==== WireGuard Device Info: %s ====", w.interfaceName)
	log.Printf("Public Key: %s", w.device.PublicKey.String())
	log.Printf("Listen Port: %d", w.device.ListenPort)
	log.Printf("Peers: %d", len(w.device.Peers))

	for i, peer := range w.device.Peers {
		log.Printf("-- Peer %d --", i+1)
		log.Printf("  Public Key: %s", peer.PublicKey.String())
		if peer.Endpoint != nil {
			log.Printf("  Endpoint: %s", peer.Endpoint.String())
		}
		log.Printf("  Allowed IPs:")
		for _, ip := range peer.AllowedIPs {
			log.Printf("    %s", ip.String())
		}
		log.Printf("  Last Handshake: %s", peer.LastHandshakeTime)
		if !peer.LastHandshakeTime.IsZero() {
			log.Printf("  Handshake Age: %s", time.Since(peer.LastHandshakeTime).Round(time.Second))
		}
		if peer.ReceiveBytes > 0 || peer.TransmitBytes > 0 {
			log.Printf("  Transfer: ↓ %d bytes ↑ %d bytes", peer.ReceiveBytes, peer.TransmitBytes)
		}
	}
	log.Println("===============================")
}

// GetDeviceInfo はデバイスの情報を返す
func (w *Manager) GetDeviceInfo() *wgtypes.Device {
	return w.device
}

// GeneratePrivateKey は新しい秘密鍵を生成する
func GeneratePrivateKey() (wgtypes.Key, error) {
	return wgtypes.GeneratePrivateKey()
}

// GenerateKeyPair は新しい鍵ペアを生成する
func GenerateKeyPair() (private wgtypes.Key, public wgtypes.Key, err error) {
	private, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}
	public = private.PublicKey()
	return private, public, nil
}
