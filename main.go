package main

import (
	"os"
)

func main() {
	//为四个节点生成公私钥
	GenRsaKeys()
	mode := os.Args[1]
	if mode == "client" {
		ClientSendMessageAndListen() //启动客户端程序
	} else if mode == "node" {
		PBFT()
	}
	select {}
}
