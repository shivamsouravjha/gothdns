package wrongid

import (
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin"
	"github.com/miekg/dns"
	"strings"
)

type Plugin struct{}

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
		// todo log

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
