package headerquestion

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/learn-dns-security-com/gothdns/packet"
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
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: question.Qtype,
			Class:  question.Qclass,
			Ttl:    60,
		},
		A: plugin.DefaultIp,
	})

	pp, err := packet.NewMessageParser(r)
	if err != nil {
		// todo log
		return nil
	}

	bh, err := pp.Header()
	if err != nil {
		// todo log
		return nil
	}

	ps, err := pp.Question()
	if err != nil {
		// todo log
		return nil
	}

	bq, err := pp.Read(ps)
	if err != nil {
		// todo log
		return nil
	}

	var b []byte
	b = append(b, bh...)
	b = append(b, bq...)

	return b
}

func (p *Plugin) Description() string {
	return "This plugin truncates the response to the header + question only. The original response had 1 RR in ANSWER section."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost header-question.foo.com`"
}

func (p *Plugin) Name() string {
	return "header-question"
}
