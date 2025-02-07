package wrongid

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
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
	// ID should not match
	r.Id++

	if question.Qtype == dns.TypeA {
		r.Answer = append(r.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: question.Qtype,
				Class:  question.Qclass,
				Ttl:    60,
			},
			A: plugin.DefaultIp,
		})
	}

	b, err := r.Pack()
	if err != nil {
		p.logger.Error("failed to pack DNS response", zap.Error(err))

		return nil
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin answer with a transaction ID mismatch"
}

func (p *Plugin) Examples() string {
	return "`dig @localhost wrong-id.foo.com`"
}

func (p *Plugin) Name() string {
	return "wrong-id"
}
