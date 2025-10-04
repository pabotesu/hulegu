package server

import (
	"github.com/spf13/cobra"
)

// RootCmd はサーバーのルートコマンドです
var RootCmd = &cobra.Command{
	Use:   "hulegu-server",
	Short: "Hulegu WireGuard over WebSocket server",
	Long:  `Huleguサーバーはクライアント間のWireGuardパケットを中継するプロキシサーバーです。`,
}

func init() {
	// サブコマンドの追加
	RootCmd.AddCommand(startCmd)
	RootCmd.AddCommand(versionCmd)
}
