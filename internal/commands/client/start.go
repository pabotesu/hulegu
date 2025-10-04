package client

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pabotesu/hulegu/pkg/client"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "クライアントを起動します",
	RunE:  runStart,
}

func init() {
	// 基本設定フラグ
	startCmd.Flags().StringP("server", "s", "", "WebSocketサーバーのURL (例: wss://example.com/ws)")
	startCmd.Flags().StringP("interface", "i", "", "使用するWireGuardインターフェース名 (例: wg0)")

	// オプション設定フラグ
	startCmd.Flags().StringP("log-level", "l", "info", "ログレベル (debug, info, warn, error)")
	startCmd.Flags().Duration("ping-interval", 30*time.Second, "Ping送信間隔")
	startCmd.Flags().StringSlice("enable-peer", nil, "有効化するピアの公開鍵（複数指定可）")
	startCmd.Flags().StringSlice("disable-peer", nil, "無効化するピアの公開鍵（複数指定可）")

	// 必須フラグのマーク
	startCmd.MarkFlagRequired("server")
	startCmd.MarkFlagRequired("interface")
}

func runStart(cmd *cobra.Command, args []string) error {
	// フラグから設定を取得
	serverURL, _ := cmd.Flags().GetString("server")
	interfaceName, _ := cmd.Flags().GetString("interface")
	pingInterval, _ := cmd.Flags().GetDuration("ping-interval")
	enablePeers, _ := cmd.Flags().GetStringSlice("enable-peer")
	disablePeers, _ := cmd.Flags().GetStringSlice("disable-peer")

	// 直接pkgの設定を作成
	config := client.DefaultConfig()
	config.ServerURL = serverURL
	config.InterfaceName = interfaceName
	config.PingInterval = pingInterval

	// ログ出力
	fmt.Printf("Starting Hulegu client\n")
	fmt.Printf("Server URL: %s\n", serverURL)
	fmt.Printf("Interface: %s\n", interfaceName)

	// 直接pkgクライアントを使用
	cli, err := client.New(config)
	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	// 有効化するピアがある場合
	for _, peerKey := range enablePeers {
		if err := cli.EnablePeer(peerKey); err != nil {
			fmt.Printf("Warning: failed to enable peer %s: %v\n", peerKey, err)
		} else {
			fmt.Printf("Enabled peer: %s\n", peerKey)
		}
	}

	// 無効化するピアがある場合
	for _, peerKey := range disablePeers {
		if err := cli.DisablePeer(peerKey); err != nil {
			fmt.Printf("Warning: failed to disable peer %s: %v\n", peerKey, err)
		} else {
			fmt.Printf("Disabled peer: %s\n", peerKey)
		}
	}

	// 接続
	if err := cli.Connect(); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer cli.Close()

	fmt.Printf("Client connected. Press Ctrl+C to exit\n")

	// シグナル待機
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Printf("Shutting down...\n")
	return nil
}
