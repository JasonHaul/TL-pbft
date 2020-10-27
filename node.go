package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/astaxie/beego/logs"
)

type Node struct {
	nodeID          string //节点ID
	nID             int
	addr            string //节点监听地址
	fnodeID         string
	faddr           string
	lock            sync.Mutex
	Level           int                 //当前节点level
	CurCount        int                 //当前处理消息数量
	fnodepp         int                 //收到子节点消息数
	CurSequence     int                 //当前消息号，只针对主节点有效
	bPrimary        bool                //是否主节点，当前节点
	rsaPrivKey      []byte              //RSA私钥
	rsaPubKey       []byte              //RSA公钥
	NodeTable       map[string]string   // key=nodeID, value=url,同级node
	SubNodeTable    map[string]string   //子级node
	NodeMsgEntrance map[int]*NodeChanel //节点每个线程对应的消息通道，接收对应消息
}

var plog = logs.NewLogger()

var k = 4
var level = 3
var NodeTable = make(map[string]*Node)

func PBFT() {
	plog.SetLogger(logs.AdapterFile, `{"filename":"pbft.log"}`)
	plog.Async()

	LevelNode := make(map[string]string)
	index := 0
	for i := 0; i < k; i++ {
		n := new(Node)
		if i == 0 {
			n.bPrimary = true
		}
		n.nID = index
		n.nodeID = "N" + strconv.Itoa(index)
		port := 8000 + index
		n.addr = "127.0.0.1:" + strconv.Itoa(port)
		n.rsaPrivKey = getPivKey(n.nodeID)
		n.rsaPubKey = getPubKey(n.nodeID)
		n.NodeMsgEntrance = make(map[int]*NodeChanel)
		n.NodeTable = make(map[string]string)
		n.Level = 1
		index++
		n.SubNodeTable = make(map[string]string)
		n.SubNodeTable = n.SubNewNode(&index, n, n.Level)
		LevelNode[n.nodeID] = n.addr
		NodeTable[n.nodeID] = n
	}

	for ID, _ := range LevelNode {
		NodeTable[ID].NodeTable = LevelNode
	}

	for _, node := range NodeTable {
		go node.TcpListen()
		fmt.Println(node.NodeTable)
		fmt.Println(node.SubNodeTable)
	}
}

func (n *Node) SubNewNode(index *int, fnode *Node, l int) map[string]string {
	LevelNode := make(map[string]string)
	l++
	for i := 0; i < k; i++ {
		node := new(Node)
		nID := *index
		node.nID = nID
		node.nodeID = "N" + strconv.Itoa(nID)
		port := 8000 + *index
		node.addr = "127.0.0.1:" + strconv.Itoa(port)
		node.rsaPrivKey = getPivKey(n.nodeID)
		node.rsaPubKey = getPubKey(n.nodeID)
		node.NodeMsgEntrance = make(map[int]*NodeChanel)
		node.NodeTable = make(map[string]string)
		node.Level = l
		node.faddr = fnode.addr
		node.fnodeID = fnode.nodeID
		*index++
		n.SubNodeTable = make(map[string]string)
		if l < level {
			node.SubNodeTable = n.SubNewNode(index, node, node.Level)
		}
		LevelNode[node.nodeID] = node.addr
		NodeTable[node.nodeID] = node
	}

	for ID, _ := range LevelNode {
		NodeTable[ID].NodeTable = LevelNode
	}

	return LevelNode
}

func (n *Node) TcpListen() {
	listen, err := net.Listen("tcp", n.addr)
	if err != nil {
		log.Panic(err)
	}
	fmt.Printf("节点开启监听，地址：%s\n", n.addr)
	plog.Info("节点开启监听，地址：%s", n.addr)
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Panic(err)
		}
		b, err := ioutil.ReadAll(conn)
		if err != nil {
			log.Panic(err)
		}
		//处理消息
		n.dispatchMsg(b)
	}

}

//将消息分发至节点各个线程,或者做相应处理
//对于每个线程设置超时时间
//对于超过多少个消息，进行舍弃（主节点）
//TODO:对于上下限距离过大的，对于下限线程进行关闭
func (n *Node) dispatchMsg(data []byte) {
	cmd, content := splitMessage(data)
	switch command(cmd) {
	case cRequest:
		n.handleRequest(content)
	case cPrePrepare:
		n.handlePrePrepare(content)
	case cPrepare:
		n.handlePrepare(data)
	case cCommit:
		n.handleCommit(data)
	}
	n.handleDisableNode()
}

func (n *Node) handleRequest(content []byte) {
	if n.Level != level && len(n.SubNodeTable) != 0 {
		if n.bPrimary {
			//n.CurSequence++
			message := jointMessage(cRequest, content)
			for i := range n.NodeTable {
				if n.nodeID == i {
					continue
				}
				tcpDial(message, n.NodeTable[i])
			}
		}

		n.broadcastSubNode(cRequest, content)
		return
	}
	if n.CurCount > 100 {
		return
	}
	//使用json解析出Request结构体
	r := new(Request)
	err := json.Unmarshal(content, r)
	if err != nil {
		log.Panic(err)
	}

	//获取消息摘要
	digest := getDigest(*r)

	//主节点对消息摘要进行签名
	digestByte, _ := hex.DecodeString(digest)
	signInfo := n.RsaSignWithSha256(digestByte, n.rsaPrivKey)
	//拼接成PrePrepare，准备发往follower节点
	pp := PrePrepare{*r, digest, r.ID, signInfo}
	n.CurSequence = pp.SequenceID
	nodeChanel := NewNodeChanel(n)
	n.lock.Lock()
	n.CurCount++
	n.NodeMsgEntrance[pp.SequenceID] = nodeChanel
	n.lock.Unlock()

	go nodeChanel.msgProcessing(&pp)
}

func (n *Node) handlePrePrepare(content []byte) {
	n.fnodepp++
	if n.fnodepp < len(n.NodeTable)/3*2 {
		return
	}
	n.fnodepp = 0
	//使用json解析出PrePrepare结构体
	pp := new(PrePrepare)
	err := json.Unmarshal(content, pp)
	if err != nil {
		log.Panic(err)
	}
	if n.nID < 6 {
		plog.Info("%s收到主节点PP消息%d", n.nodeID, pp.SequenceID)
	}
	//plog.Info("%s收到主节点PP消息%d", n.nodeID, pp.SequenceID)

	n.CurSequence = pp.SequenceID
	nodeChanel := NewNodeChanel(n)
	n.lock.Lock()
	n.CurCount++
	n.NodeMsgEntrance[pp.SequenceID] = nodeChanel
	n.lock.Unlock()

	go nodeChanel.msgProcessing(pp)
}

func (n *Node) handlePrepare(data []byte) {
	//使用json解析出Prepare结构体
	_, content := splitMessage(data)
	pre := new(Prepare)
	err := json.Unmarshal(content, pre)
	if err != nil {
		log.Panic(err)
	}
	//plog.Info("%s收到%sPre消息%d", n.nodeID, pre.NodeID, pre.SequenceID)

	go func() {
		for i := 0; i <= 10; i++ {
			n.lock.Lock()
			nodechan, ok := n.NodeMsgEntrance[pre.SequenceID]
			n.lock.Unlock()
			if ok {
				nodechan.MsgEntrance <- data
				return
			}
			time.Sleep(time.Second * 1)
		}
	}()
}

func (n *Node) handleCommit(data []byte) {
	//使用json解析出Commit结构体
	_, content := splitMessage(data)
	c := new(Commit)
	err := json.Unmarshal(content, c)
	if err != nil {
		log.Panic(err)
	}
	//plog.Info("%s收到%sC消息%d", n.nodeID, c.NodeID, c.SequenceID)

	go func() {
		for i := 0; i <= 10; i++ {
			n.lock.Lock()
			nodechan, ok := n.NodeMsgEntrance[c.SequenceID]
			n.lock.Unlock()
			if ok {
				nodechan.MsgEntrance <- data
				return
			}
			time.Sleep(time.Second * 1)
		}
	}()
}

func (n *Node) handleDisableNode() {

}

func (n *Node) broadcast(cmd command, content []byte) {
	message := jointMessage(cmd, content)
	for i := range n.NodeTable {
		tcpDial(message, n.NodeTable[i])
	}
}

func (n *Node) broadcastSubNode(cmd command, content []byte) {
	message := jointMessage(cmd, content)
	for i := range n.SubNodeTable {
		tcpDial(message, n.SubNodeTable[i])
	}
}
