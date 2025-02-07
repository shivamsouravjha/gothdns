package plugintest

import (
	"github.com/miekg/dns"
	"math/rand"
	"net"
)

type BytesReceived [][]byte

func (l BytesReceived) Shift() []byte {
	if len(l) == 0 {
		return nil
	}

	v := l[0]
	l = l[1:]

	return v
}

type MessagesReceived []*dns.Msg

func (l MessagesReceived) Shift() *dns.Msg {
	if len(l) == 0 {
		return nil
	}

	v := l[0]
	l = l[1:]

	return v
}

type ResponseWriter struct {
	Bytes    BytesReceived
	Messages MessagesReceived
}

func (w *ResponseWriter) LocalAddr() net.Addr {
	return &net.IPNet{}
}

func (w *ResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: rand.Intn(50000) + 1024,
	}
}

func (w *ResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.Messages = append(w.Messages, msg)

	return nil
}

func (w *ResponseWriter) Write(b []byte) (int, error) {
	w.Bytes = append(w.Bytes, b)

	return 0, nil
}

func (w *ResponseWriter) Close() error {
	return nil
}

func (w *ResponseWriter) TsigStatus() error {
	return nil
}

func (w *ResponseWriter) TsigTimersOnly(bool) {

}

func (w *ResponseWriter) Hijack() {

}
