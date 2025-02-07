package plugin

import (
	"errors"
	"github.com/miekg/dns"
)

func ReplyWithDefaultARecord(m *dns.Msg) ([]byte, error) {
	question := m.Question[0]

	r := new(dns.Msg)
	r.SetReply(m)
	r.Answer = append(r.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   question.Name,
			Rrtype: question.Qtype,
			Class:  question.Qclass,
			Ttl:    60,
		},
		A: DefaultIp,
	})

	b, err := r.Pack()
	if err != nil {
		return nil, errors.New("failed to pack DNS response: " + err.Error())
	}

	return b, nil
}
