package packet

import (
	"fmt"
	"github.com/learn-dns-security-com/gothdns/binary"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestPacketParser_Question(t *testing.T) {
	t.Run("no question", func(t *testing.T) {
		m := new(dns.Msg)

		pp, err := NewMessageParser(m)
		require.NoError(t, err)

		_, err = pp.Question()
		require.Error(t, ErrQuestionNotFound)
	})

	t.Run("2 questions", func(t *testing.T) {
		m := new(dns.Msg)
		m.Id = dns.Id()
		m.RecursionDesired = true
		m.Question = make([]dns.Question, 2)
		m.Question[0] = dns.Question{Name: dns.Fqdn("google.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}
		m.Question[1] = dns.Question{Name: dns.Fqdn("google.com"), Qtype: dns.TypeA, Qclass: dns.ClassINET}

		pp, err := NewMessageParser(m)
		require.NoError(t, err)

		_, err = pp.Question()
		require.Error(t, ErrMultipleQuestionFound)
	})

	t.Run("domain no answer", func(t *testing.T) {
		for _, domain := range []string{
			"example.co.uk", "example.com", ".", "com",
		} {
			t.Run(domain, func(t *testing.T) {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)

				pp, err := NewMessageParser(m)
				require.NoError(t, err)

				ps, err := pp.Question()
				require.NoError(t, err)

				b, err := pp.Read(ps)
				require.NoError(t, err)

				q := m.Question[0]

				bits := binary.Qname(q.Name) + " " +
					binary.Uint16(q.Qtype) + " " +
					binary.Uint16(q.Qclass)

				assert.Equal(t,
					"["+bits+"]",
					fmt.Sprintf("%.8b", b),
				)
			})
		}
	})

	t.Run("domain + answer", func(t *testing.T) {
		for _, domain := range []string{
			"example.co.uk", "example.com", ".", "com",
		} {
			t.Run(domain, func(t *testing.T) {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn("example.com"), dns.TypeNS)
				m.Response = true

				question := m.Question[0]
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: question.Qtype,
						Class:  question.Qclass,
						Ttl:    60,
					},
					A: net.ParseIP("127.0.0.1"),
				})

				pp, err := NewMessageParser(m)
				require.NoError(t, err)

				ps, err := pp.Question()
				require.NoError(t, err)

				b, err := pp.Read(ps)
				require.NoError(t, err)

				q := m.Question[0]

				bits := binary.Qname(q.Name) + " " +
					binary.Uint16(q.Qtype) + " " +
					binary.Uint16(q.Qclass)

				assert.Equal(t,
					"["+bits+"]",
					fmt.Sprintf("%.8b", b),
				)
			})
		}
	})
}

func TestPacketParser_Answer(t *testing.T) {
	t.Run("1 answer", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("example.com"), dns.TypeNS)
		m.Response = true

		question := m.Question[0]
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: question.Qtype,
				Class:  question.Qclass,
				Ttl:    60,
			},
			A: net.ParseIP("127.0.0.1"),
		})

		pp, err := NewMessageParser(m)
		require.NoError(t, err)

		ps, err := pp.Answer()
		require.NoError(t, err)

		b, err := pp.Read(ps)
		require.NoError(t, err)

		q := m.Question[0]

		assert.Equal(t,
			"["+
				binary.Qname(q.Name)+" "+
				binary.Uint16(dns.TypeNS)+" "+
				binary.Uint16(dns.ClassINET)+" "+
				binary.Uint32(60)+" "+ // ttl
				"00000000 00000100 "+ // rdlength 4 bytes
				"01111111 00000000 00000000 00000001"+ // 127.0.0.1
				"]",
			fmt.Sprintf("%.8b", b),
		)
	})

	t.Run("2 answers", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("example.com"), dns.TypeNS)
		m.Response = true

		question := m.Question[0]
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: question.Qtype,
				Class:  question.Qclass,
				Ttl:    60,
			},
			A: net.ParseIP("127.0.0.1"),
		})
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: question.Qtype,
				Class:  question.Qclass,
				Ttl:    60,
			},
			A: net.ParseIP("127.0.0.2"),
		})

		pp, err := NewMessageParser(m)
		require.NoError(t, err)

		ps, err := pp.Answer()
		require.NoError(t, err)

		b, err := pp.Read(ps)
		require.NoError(t, err)

		q := m.Question[0]

		assert.Equal(t,
			"["+
				// first one
				binary.Qname(q.Name)+" "+
				binary.Uint16(dns.TypeNS)+" "+
				binary.Uint16(dns.ClassINET)+" "+
				binary.Uint32(60)+" "+ // ttl
				"00000000 00000100 "+ // rdlength 4 bytes
				"01111111 00000000 00000000 00000001 "+ // 127.0.0.1

				// second one
				binary.Qname(q.Name)+" "+
				binary.Uint16(dns.TypeNS)+" "+
				binary.Uint16(dns.ClassINET)+" "+
				binary.Uint32(60)+" "+ // ttl
				"00000000 00000100 "+ // rdlength 4 bytes
				"01111111 00000000 00000000 00000010"+ // 127.0.0.2
				"]",
			fmt.Sprintf("%.8b", b),
		)
	})
}
