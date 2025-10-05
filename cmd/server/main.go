package main

import (
	"fmt"
	"os"

	"github.com/pabotesu/hulegu/internal/commands/server"
)

// Version はビルド時に設定されるバージョン情報
var Version = "0.1.0"

func main() {
	// バージョン情報を設定
	server.Version = Version

	// コマンドを実行
	if err := server.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
