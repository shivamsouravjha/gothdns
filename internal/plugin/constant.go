package plugin

import "net"

type Violation struct {
	Identifier string
	Link       string
}

var DropPacket = []byte("drop")

var DefaultIp = net.ParseIP("127.0.0.1")
