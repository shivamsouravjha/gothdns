package nodobitsupport

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, false)

		p := new(Plugin)
		b := p.Reply(m)
		require.NotNil(t, b)

		r := new(dns.Msg)
		err := r.Unpack(b)
		require.NoError(t, err)

		require.Equal(t, dns.RcodeNameError, r.Rcode)
	})

	t.Run("unhappy path", func(t *testing.T) {
		t.Run("not type A", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeTXT)
			m.Id = 12345
			m.SetEdns0(1232, false)

			p := new(Plugin)
			b := p.Reply(m)
			require.Nil(t, b)
		})

		t.Run("DO bit to 1", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
			m.Id = 12345
			m.SetEdns0(1232, true)

			p := new(Plugin)
			b := p.Reply(m)
			require.NotNil(t, b)

			r := new(dns.Msg)
			err := r.Unpack(b)
			require.NoError(t, err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
			require.Equal(t, 1, len(r.Answer), r.String())
			assert.Equal(t, "127.0.0.1", r.Answer[0].(*dns.A).A.String(), r.String())
		})

		t.Run("no EDNS", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
			m.Id = 12345

			p := new(Plugin)
			b := p.Reply(m)
			require.NotNil(t, b)

			r := new(dns.Msg)
			err := r.Unpack(b)
			require.NoError(t, err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
			require.Equal(t, 1, len(r.Answer), r.String())
			assert.Equal(t, "127.0.0.1", r.Answer[0].(*dns.A).A.String(), r.String())
		})
	})
}
