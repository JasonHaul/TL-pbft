package main

import (
	"encoding/json"
	"log"
)

type State int

const (
	Idle        State = iota // Node is created successfully, but the consensus process is not started yet.
	PrePrepared              // The ReqMsgs is processed successfully. The node is ready to head to the Prepare stage.
	Prepared                 // Same with `prepared` stage explained in the original paper.
	Committed                // Same with `committed-local` stage explained in the original paper.
)

type NodeChanel struct {
	node         *Node
	MsgSequence  int
	CurState     State
	Digest       string
	Content      string
	Sign         []byte
	PrepareCount int
	CommitCount  int
	MsgEntrance  chan []byte
}

func NewNodeChanel(node *Node) *NodeChanel {
	n := new(NodeChanel)
	n.node = node
	n.CurState = Idle
	n.MsgEntrance = make(chan []byte)
	return n
}

func (n *NodeChanel) msgProcessing(pp *PrePrepare) {
	n.CurState = PrePrepared
	n.Digest = pp.Digest
	n.MsgSequence = pp.SequenceID
	n.Sign = pp.Sign
	n.Content = pp.RequestMessage.Content
	pre := Prepare{pp.Digest, pp.SequenceID, n.node.nodeID, pp.Sign}
	bPre, err := json.Marshal(pre)
	if err != nil {
		log.Panic(err)
	}
	n.node.broadcast(cPrepare, bPre)

	for msg := range n.MsgEntrance {
		cmd, content := splitMessage(msg)
		switch command(cmd) {
		case cPrepare:
			if n.CurState == Committed {
				break
			}
			pre := new(Prepare)
			err := json.Unmarshal(content, pre)
			if err != nil {
				log.Panic(err)
			}
			n.CurState = Prepared
			n.PrepareCount++
			if n.node.nID < 6 {
				plog.Info("%s节点%d通道收到%s消息", n.node.nodeID, pre.SequenceID, pre.NodeID)
			}

			if n.PrepareCount > len(n.node.NodeTable)/3*2 {
				c := Commit{pre.Digest, pre.SequenceID, n.node.nodeID, pre.Sign}
				bc, err := json.Marshal(c)
				if err != nil {
					log.Panic(err)
				}
				n.node.broadcast(cCommit, bc)
				n.CurState = Committed
				//plog.Info("%s已发送Commit消息%d", n.node.nodeID, n.MsgSequence)
			}
		case cCommit:
			c := new(Commit)
			err := json.Unmarshal(content, c)
			if err != nil {
				log.Panic(err)
			}
			n.CommitCount++
			if n.CurState != Committed {
				break
			}
			if n.CommitCount > len(n.node.NodeTable)/3*2 {
				if n.node.Level == 1 {
					r := new(Reply)
					r.Content = n.Content
					r.NodeID = n.node.nodeID
					r.Message.ID = n.MsgSequence
					br, err := json.Marshal(r)
					if err != nil {
						log.Panic(err)
					}
					cont := jointMessage(cReply, br)
					tcpDial(cont, "127.0.0.1:8888")
				} else {
					bPP, err := json.Marshal(pp)
					if err != nil {
						log.Panic(err)
					}
					cont := jointMessage(cPrePrepare, bPP)
					tcpDial(cont, n.node.faddr)
					//plog.Info("%s节点已发送至父节点%s", n.node.nodeID, n.node.fnodeID)
				}
				n.node.lock.Lock()
				n.node.CurCount--
				delete(n.node.NodeMsgEntrance, n.MsgSequence)
				n.node.lock.Unlock()
				if n.node.nID < 6 {
					plog.Info("%s已发送Reply消息%d,当前运行中%d,父节点%d", n.node.nodeID, n.MsgSequence, n.node.CurCount, n.node.fnodeID)
				}
				return
			}
		}
	}

}
