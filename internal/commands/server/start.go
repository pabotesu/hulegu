package server

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pabotesu/hulegu/pkg/server"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "サーバーを起動します",
	RunE:  runStart,
}

func init() {
	// 基本設定フラグ
	startCmd.Flags().StringP("addr", "a", ":8080", "リッスンアドレス (例: :8080)")
	startCmd.Flags().StringP("path", "p", "/ws", "WebSocketエンドポイントのパス")

	// セキュリティ設定
	startCmd.Flags().String("tls-cert", "", "TLS証明書ファイル")
	startCmd.Flags().String("tls-key", "", "TLS秘密鍵ファイル")
	startCmd.Flags().String("allow-list", "", "カンマ区切りの許可ピア公開鍵リスト")

	// 詳細設定
	startCmd.Flags().StringP("log-level", "l", "info", "ログレベル (debug, info, warn, error)")
	startCmd.Flags().Duration("session-timeout", 24*time.Hour, "セッションタイムアウト")
	startCmd.Flags().Int("max-connections", 0, "最大接続数（0は無制限）")
}

func runStart(cmd *cobra.Command, args []string) error {
	// フラグから設定を取得
	addr, _ := cmd.Flags().GetString("addr")
	path, _ := cmd.Flags().GetString("path")
	logLevel, _ := cmd.Flags().GetString("log-level")
	tlsCert, _ := cmd.Flags().GetString("tls-cert")
	tlsKey, _ := cmd.Flags().GetString("tls-key")
	allowList, _ := cmd.Flags().GetString("allow-list")
	sessionTimeout, _ := cmd.Flags().GetDuration("session-timeout")
	maxConn, _ := cmd.Flags().GetInt("max-connections")

	// 許可リストの処理
	var allowedPeers []string
	if allowList != "" {
		allowedPeers = strings.Split(allowList, ",")
		for i := range allowedPeers {
			allowedPeers[i] = strings.TrimSpace(allowedPeers[i])
		}
	}

	// サーバー設定の作成
	config := server.DefaultConfig()
	config.ListenAddr = addr
	config.Path = path
	config.LogLevel = logLevel
	config.TLSCertFile = tlsCert
	config.TLSKeyFile = tlsKey
	config.AllowedPeers = allowedPeers
	config.SessionTimeout = sessionTimeout
	config.MaxConnections = maxConn

	fmt.Printf("Starting Hulegu server on %s%s\n", addr, path)
	fmt.Printf("Log level: %s\n", logLevel)

	if tlsCert != "" && tlsKey != "" {
		fmt.Printf("TLS enabled with certificate: %s\n", tlsCert)
	} else {
		fmt.Printf("TLS disabled\n")
	}

	if len(allowedPeers) > 0 {
		fmt.Printf("Allowed peers: %d peer(s)\n", len(allowedPeers))
	} else {
		fmt.Printf("All peers allowed\n")
	}

	// サーバー作成
	srv, err := server.New(config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// 非同期でサーバーを開始
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// シグナル待機
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// シグナルかエラーを待機
	select {
	case <-sigCh:
		fmt.Printf("Received signal, shutting down...\n")
	case err := <-errCh:
		fmt.Printf("Server error: %v\n", err)
		return err
	}

	// シャットダウン
	if err := srv.Stop(); err != nil {
		fmt.Printf("Error during shutdown: %v\n", err)
	}

	return nil
}
