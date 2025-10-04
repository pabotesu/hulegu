package client

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Packet はUDPパケットとその送信元を表します
type Packet struct {
	Data     []byte
	Src      *net.UDPAddr
	RecvTime time.Time
}

// HuleguEndpoint はピア用のWireGuardパケット受付口を提供します
type HuleguEndpoint struct {
	conn        *net.UDPConn
	listenAddr  string
	wgAddr      *net.UDPAddr // WireGuardインターフェースのアドレス
	recvPackets chan *Packet
	isClosed    bool
	mu          sync.RWMutex
	wg          sync.WaitGroup
}

// NewHuleguEndpoint は新しいエンドポイントを作成します
func NewHuleguEndpoint(listenAddr string, wgEndpoint string) (*HuleguEndpoint, error) {
	// リスニングアドレスの解析
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve listen address: %w", err)
	}

	// WireGuardエンドポイントの解析
	wgAddr, err := net.ResolveUDPAddr("udp", wgEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve WireGuard endpoint: %w", err)
	}

	// UDPソケットのリッスン
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on UDP socket: %w", err)
	}

	// バッファサイズの設定
	const (
		udpBufferSize = 65535 // 最大UDPパケットサイズ
		channelBuffer = 1024  // 受信チャネルバッファサイズ
	)

	// バッファサイズの増加（オプション）
	conn.SetReadBuffer(udpBufferSize * 2)
	conn.SetWriteBuffer(udpBufferSize * 2)

	// エンドポイントの作成
	endpoint := &HuleguEndpoint{
		conn:        conn,
		listenAddr:  listenAddr,
		wgAddr:      wgAddr,
		recvPackets: make(chan *Packet, channelBuffer),
		isClosed:    false,
	}

	// パケット受信用のgoroutineを開始
	endpoint.wg.Add(1)
	go endpoint.readLoop()

	log.Printf("Hulegu endpoint listening on %s, forwarding to WireGuard at %s",
		conn.LocalAddr().String(), wgEndpoint)
	return endpoint, nil
}

// readLoop はUDPパケットを継続的に読み込みます
func (h *HuleguEndpoint) readLoop() {
	defer h.wg.Done()

	buf := make([]byte, 65535) // UDPの最大パケットサイズ

	for {
		h.mu.RLock()
		isClosed := h.isClosed
		h.mu.RUnlock()

		if isClosed {
			return
		}

		// タイムアウトを設定（クローズ検出のため）
		h.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		// パケットの読み込み
		n, src, err := h.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// タイムアウトは無視して継続
				continue
			}

			h.mu.RLock()
			isClosed := h.isClosed
			h.mu.RUnlock()

			if !isClosed {
				log.Printf("UDP read error: %v", err)
			}
			continue
		}

		// パケットデータのコピー
		data := make([]byte, n)
		copy(data, buf[:n])

		// 受信パケットの作成
		packet := &Packet{
			Data:     data,
			Src:      src,
			RecvTime: time.Now(),
		}

		// WireGuardからのパケットかどうかを確認
		isFromWireGuard := src.IP.Equal(h.wgAddr.IP) && src.Port == h.wgAddr.Port

		// パケットをチャネルに送信
		select {
		case h.recvPackets <- packet:
			// パケットをチャネルに送信成功
			if isFromWireGuard {
				log.Printf("Received packet from WireGuard (%d bytes)", len(data))
			}
		default:
			// バッファがいっぱいの場合は破棄
			log.Printf("Packet buffer full, dropping packet from %s", src.String())
		}
	}
}

// ReadPacket は受信したパケットを返します
func (h *HuleguEndpoint) ReadPacket() (*Packet, error) {
	packet, ok := <-h.recvPackets
	if !ok {
		return nil, fmt.Errorf("endpoint is closed")
	}
	return packet, nil
}

// WriteToWireGuard はパケットをWireGuardに送信します
func (h *HuleguEndpoint) WriteToWireGuard(data []byte) (int, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.isClosed {
		return 0, fmt.Errorf("endpoint is closed")
	}

	return h.conn.WriteToUDP(data, h.wgAddr)
}

// Close はエンドポイントを閉じます
func (h *HuleguEndpoint) Close() error {
	h.mu.Lock()
	if !h.isClosed {
		h.isClosed = true
		close(h.recvPackets)
	}
	h.mu.Unlock()

	err := h.conn.Close()
	h.wg.Wait() // readLoopの終了を待つ
	return err
}

// LocalAddr はリスニングアドレスを返します
func (h *HuleguEndpoint) LocalAddr() net.Addr {
	return h.conn.LocalAddr()
}

// WireGuardAddr はWireGuardのエンドポイントアドレスを返します
func (h *HuleguEndpoint) WireGuardAddr() *net.UDPAddr {
	return h.wgAddr
}

// SetWireGuardEndpoint はWireGuardのエンドポイントを変更します
func (h *HuleguEndpoint) SetWireGuardEndpoint(endpoint string) error {
	wgAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return fmt.Errorf("failed to resolve WireGuard endpoint: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	h.wgAddr = wgAddr
	log.Printf("Updated WireGuard endpoint to %s", endpoint)
	return nil
}

// IsFromWireGuard はパケットがWireGuardから来たものかを判定します
func (h *HuleguEndpoint) IsFromWireGuard(packet *Packet) bool {
	return packet.Src.IP.Equal(h.wgAddr.IP) && packet.Src.Port == h.wgAddr.Port
}

// GetStats はエンドポイントの統計情報を返します
func (h *HuleguEndpoint) GetStats() (packetCount int, err error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return len(h.recvPackets), nil
}
