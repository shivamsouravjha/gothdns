package staticip

import (
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"net"
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
	if question.Qtype != dns.TypeA {
		return nil
	}

	labels := strings.Split(question.Name, ".")
	if strings.ToLower(labels[0]) != p.Name() {
		return nil
	}

	ip := plugin.DefaultIp
	if len(labels) >= 5 {
		if i := net.ParseIP(strings.Join(labels[1:5], ".")); i != nil {
			ip = i
		}
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
		A: ip,
	})

	b, err := r.Pack()
	if err != nil {
		p.logger.Error("failed to pack DNS response", zap.Error(err))

		return nil
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin allow you to get returned a static IP (by default `127.0.0.1`) or define your own from the query.\n" +
		"Only support A record for now."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost static-ip.foo.com` or `dig @localhost static-ip.1.2.3.4.foo.com` to get `1.2.3.4` back in the ANSWER section."
}

func (p *Plugin) Name() string {
	return "static-ip"
}
