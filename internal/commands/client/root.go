package client

import (
	"fmt"
	"time"

	"github.com/pabotesu/hulegu/pkg/client"
	"github.com/spf13/cobra"
)

// RootCmd はクライアントのルートコマンドです
var RootCmd = &cobra.Command{
	Use:   "hulegu-client",
	Short: "Hulegu WireGuard over WebSocket client",
	Long:  `Huleguクライアントはファイアウォール制限のある環境でWireGuardを使用するためのプロキシです。`,
}

func init() {
	// サブコマンドの追加
	RootCmd.AddCommand(startCmd)
	RootCmd.AddCommand(enablePeerCmd)
	RootCmd.AddCommand(disablePeerCmd)
	RootCmd.AddCommand(listPeersCmd)
	RootCmd.AddCommand(versionCmd)
}

// 共通のクライアント作成関数
func createClient(cmd *cobra.Command) (*client.Client, error) {
	serverURL, _ := cmd.Flags().GetString("server")
	interfaceName, _ := cmd.Flags().GetString("interface")

	config := client.DefaultConfig()
	config.ServerURL = serverURL
	config.InterfaceName = interfaceName
	config.PingInterval = 30 * time.Second

	// logLevelは使用しない

	cli, err := client.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	// 接続
	if err := cli.Connect(); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	return cli, nil
}
