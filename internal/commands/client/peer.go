package client

import (
	"fmt"

	"github.com/spf13/cobra"
)

var enablePeerCmd = &cobra.Command{
	Use:   "enable-peer [PEER_KEY]",
	Short: "ピアを有効化します",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnablePeer,
}

var disablePeerCmd = &cobra.Command{
	Use:   "disable-peer [PEER_KEY]",
	Short: "ピアを無効化します",
	Args:  cobra.ExactArgs(1),
	RunE:  runDisablePeer,
}

var listPeersCmd = &cobra.Command{
	Use:   "list-peers",
	Short: "有効なピア一覧を表示します",
	RunE:  runListPeers,
}

func init() {
	// 共通フラグの設定
	for _, cmd := range []*cobra.Command{enablePeerCmd, disablePeerCmd, listPeersCmd} {
		cmd.Flags().StringP("server", "s", "", "WebSocketサーバーのURL (例: wss://example.com/ws)")
		cmd.Flags().StringP("interface", "i", "", "使用するWireGuardインターフェース名 (例: wg0)")
		cmd.Flags().StringP("log-level", "l", "info", "ログレベル")

		// 必須フラグのマーク
		cmd.MarkFlagRequired("server")
		cmd.MarkFlagRequired("interface")
	}
}

// ピア有効化コマンドの処理
func runEnablePeer(cmd *cobra.Command, args []string) error {
	peerKey := args[0]

	cli, err := createClient(cmd)
	if err != nil {
		return err
	}
	defer cli.Close()

	if err := cli.EnablePeer(peerKey); err != nil {
		return fmt.Errorf("failed to enable peer: %w", err)
	}

	fmt.Printf("Peer %s enabled\n", peerKey)
	return nil
}

// ピア無効化コマンドの処理
func runDisablePeer(cmd *cobra.Command, args []string) error {
	peerKey := args[0]

	cli, err := createClient(cmd)
	if err != nil {
		return err
	}
	defer cli.Close()

	if err := cli.DisablePeer(peerKey); err != nil {
		return fmt.Errorf("failed to disable peer: %w", err)
	}

	fmt.Printf("Peer %s disabled\n", peerKey)
	return nil
}

// ピア一覧表示コマンドの処理
func runListPeers(cmd *cobra.Command, args []string) error {
	cli, err := createClient(cmd)
	if err != nil {
		return err
	}
	defer cli.Close()

	peers := cli.GetEnabledPeers()

	if len(peers) == 0 {
		fmt.Println("No enabled peers found")
	} else {
		fmt.Println("Enabled peers:")
		for i, peer := range peers {
			fmt.Printf("  %d. %s\n", i+1, peer)
		}
	}

	return nil
}
