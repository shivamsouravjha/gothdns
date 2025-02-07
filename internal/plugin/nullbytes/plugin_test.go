package nullbytes

import (
	"fmt"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Run("1 len", func(t *testing.T) {
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
				t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn("null-bytes.foo.com"), qt)

					p := NewPlugin(zap.NewNop())
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

					p := NewPlugin(zap.NewNop())
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

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			require.NotNil(t, b)
			assert.Len(t, b, 1)
			assert.Equal(t, "[00000000]", fmt.Sprintf("%.8b", b))
		})
	})

	t.Run("unhappy path", func(t *testing.T) {
		t.Run("nil message", func(t *testing.T) {
			p := NewPlugin(zap.NewNop())
			b := p.Reply(nil)
			require.Nil(t, b)
		})

		t.Run("0 questions", func(t *testing.T) {
			p := NewPlugin(zap.NewNop())
			b := p.Reply(new(dns.Msg))
			require.Nil(t, b)
		})
	})
}
