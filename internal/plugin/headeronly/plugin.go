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
	p := new(Plugin)
	p.logger = logger.With(zap.String("plugin", p.Name()))

	return p
}

func (p *Plugin) Reply(m *dns.Msg) []byte {
	if m == nil {
		return nil
	}
	if len(m.Question) != 1 {
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
		p.logger.Error("failed to parse DNS response", zap.Error(err))

		return nil
	}

	b, err := mp.Header()
	if err != nil {
		p.logger.Error("failed to parse DNS header", zap.Error(err))

		return nil
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin truncates the response to the header only. The original response had 1 RR in ANSWER section."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost headeronly.foo.com`"
}

func (p *Plugin) Name() string {
	return "headeronly"
}
