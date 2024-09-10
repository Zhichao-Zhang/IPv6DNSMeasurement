// custom dns authority server
package main

import (
	"Dual_Stack_DNS_Discovery/cudas/internal/server"
	"fmt"
	"github.com/gogf/gf/v2/os/gcmd"
)

func main() {
	args := gcmd.GetArgAll()
	if len(args) >= 2 && args[1] == "help" {
		fmt.Print(HelpStr + "\n")
		return
	}
	mode := gcmd.GetOpt("m").String()
	allow_mode_types := map[string]bool{"cudas": true}
	if _, exists := allow_mode_types[mode]; exists {
		fmt.Printf("starting the [auth %s] server ... \n", mode)
		server.Main(mode)
	} else {
		print("ERROR : Mode input (-m) is not expected!")
		return
	}

}

const HelpStr = `USAGE 
    go run main SubCommand [OPTION]
	SubCommand
		help			打印帮助信息
	OPTION [mode]
		-m				指定权威服务器模式（可选：cudas, client, measurement ...对应测量模型的权威）
	EXAMPLES
		go run main -m A
		go run main -m B
		go run main help
		go run cmd/server/main.go parser 解析log，分析结果
`
