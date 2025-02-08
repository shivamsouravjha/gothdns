package internal

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugintest"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestHandler(t *testing.T) {
	t.Run("no suitable plugins", func(t *testing.T) {
		w := new(plugintest.ResponseWriter)

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("bar.foo.com"), dns.TypeA)

		rh := NewRequestHandler(zap.NewNop())
		rh.ServeDNS(w, m)

		r := w.Messages.Shift()

		require.NotNil(t, r)
		assert.Equal(t, dns.RcodeRefused, r.Rcode, r.String())
	})

	t.Run("call registered module", func(t *testing.T) {
		w := new(plugintest.ResponseWriter)

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("static-ip.foo.com"), dns.TypeA)

		rh := NewRequestHandler(zap.NewNop())
		rh.ServeDNS(w, m)

		b := w.Bytes.Shift()

		r := new(dns.Msg)
		require.NoError(t, r.Unpack(b))

		require.NotNil(t, r)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
		require.Equal(t, 1, len(r.Answer), r.String())
		assert.Equal(t, "127.0.0.1", r.Answer[0].(*dns.A).A.String(), r.String())
	})
}

func TestRequestHandler_Plugins(t *testing.T) {
	count := 0
	files, err := os.ReadDir("/app/internal/plugin")
	require.NoError(t, err)
	for _, file := range files {
		if file.IsDir() {
			count++
		}
	}

	rh := NewRequestHandler(zap.NewNop())
	require.Equal(t, count, len(rh.Plugins()))
}
