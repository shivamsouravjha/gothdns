package echo

import (
    "github.com/miekg/dns"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.uber.org/zap"
    "testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("echo.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)
		require.NotNil(t, b)

		bm, err := m.Pack()
		require.NoError(t, err)

		assert.Equal(t, bm, b)
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

// Test generated using Keploy
func TestPlugin_Reply_InvalidFirstLabel(t *testing.T) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn("invalid.foo.com"), dns.TypeA)
    m.Id = 12345
    m.SetEdns0(1232, true)

    p := NewPlugin(zap.NewNop())
    b := p.Reply(m)
    require.Nil(t, b)
}


// Test generated using Keploy
func TestPlugin_Description(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    desc := p.Description()
    require.Equal(t, "This plugin reply the exact same bytes it receives.", desc)
}


// Test generated using Keploy
func TestPlugin_Examples(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    example := p.Examples()
    require.Equal(t, "`dig @localhost echo.foo.com`", example)
}

