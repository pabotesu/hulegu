package client

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version はビルド時に設定されるバージョン情報
var Version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "バージョン情報を表示",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Hulegu Client v" + Version)
	},
}
