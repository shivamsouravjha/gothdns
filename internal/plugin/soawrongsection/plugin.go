package soawrongsection

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
	if len(m.Question) != 1 {
		return nil
	}

	question := m.Question[0]
	if question.Qtype != dns.TypeSOA {
		return nil
	}

	labels := strings.Split(question.Name, ".")
	if strings.ToLower(labels[0]) != p.Name() {
		return nil
	}

	r := new(dns.Msg)
	r.SetReply(m)
	r.Ns = append(r.Ns, &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: question.Qtype,
			Class:  question.Qclass,
			Ttl:    60,
		},
		Ns:      "ns." + strings.Join(labels[1:], "."),
		Mbox:    "hostmaster." + strings.Join(labels[1:], "."),
		Serial:  20240207,
		Refresh: 3600,
		Retry:   3600,
		Expire:  3600,
		Minttl:  3600,
	})

	b, err := r.Pack()
	if err != nil {
		p.logger.Error("failed to pack DNS response", zap.Error(err))

		return nil
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin reply to SOA query by setting up the SOA in AUTHORITY section rather than ANSWER.\nSupport for SOA record only."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost soa-wrong-section.foo.com`"
}

func (p *Plugin) Name() string {
	return "soa-wrong-section"
}

func (p *Plugin) DNSViolation() plugin.Violation {
	return plugin.Violation{
		Identifier: "DVE-2020-0002",
		Link:       "https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0002.md",
	}
}
