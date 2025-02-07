package headeronly

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/learn-dns-security-com/gothdns/packet"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"strings"
)

type Plugin struct {
	logger *zap.Logger
}

func NewPlugin(logger *zap.Logger) *Plugin {
	return &Plugin{
		logger: logger,
	}
}

func (p *Plugin) Reply(m *dns.Msg) []byte {
	if m == nil {
		return nil
	}
	if len(m.Question) == 0 {
		return nil
	}

	question := m.Question[0]
	labels := strings.Split(question.Name, ".")
	if strings.ToLower(labels[0]) != p.Name() {
		return nil
	}

	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: question.Qtype,
			Class:  question.Qclass,
			Ttl:    60,
		},
		A: plugin.DefaultIp,
	})

	mp, err := packet.NewMessageParser(r)
	if err != nil {
		// todo log

		return nil
	}

	b, err := mp.Header()
	if err != nil {
		// todo log

		return nil
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin truncates the response to the header only. The original response had 1 RR in ANSWER section."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost header-only.foo.com`"
}

func (p *Plugin) Name() string {
	return "header-only"
}
