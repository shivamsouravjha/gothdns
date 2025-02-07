package nullbytes

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Run("1 len", func(t *testing.T) {
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
				t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn("null-bytes.foo.com"), qt)

					p := new(Plugin)
					b := p.Reply(m)

					require.NotNil(t, b)
					assert.Len(t, b, 1)
					assert.Equal(t, "[0]", fmt.Sprint(b))
				})
			}
		})

		t.Run("8 len", func(t *testing.T) {
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
				t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn("null-bytes.8.foo.com"), dns.TypeA)

					p := new(Plugin)
					b := p.Reply(m)

					require.NotNil(t, b)
					assert.Len(t, b, 8)
					assert.Equal(t, "[00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000]", fmt.Sprintf("%.8b", b))
				})
			}
		})

		t.Run("mix subdomain numbers and letters", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("null-bytes.8d.foo.com"), dns.TypeA)

			p := new(Plugin)
			b := p.Reply(m)

			require.NotNil(t, b)
			assert.Len(t, b, 1)
			assert.Equal(t, "[00000000]", fmt.Sprintf("%.8b", b))
		})
	})
}
