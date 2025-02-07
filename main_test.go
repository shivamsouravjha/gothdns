package main

import (
	"context"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	t.Run("static-ip", func(t *testing.T) {
		for _, protocol := range []string{"udp", "tcp"} {
			t.Run(protocol, func(t *testing.T) {
				defer goleak.VerifyNone(t)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				logger := zap.NewNop()

				go Run(ctx, logger)

				// let the server start
				time.Sleep(time.Millisecond * 200)

				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn("static-ip.foo.com"), dns.TypeA)

				c := new(dns.Client)
				c.Net = protocol
				r, _, err := c.Exchange(m, "127.0.0.1:53")
				require.NoError(t, err)

				require.Equal(t, dns.RcodeSuccess, r.Rcode)
				require.Equal(t, 1, len(r.Answer))
				require.Equal(t, `static-ip.foo.com.	60	IN	A	127.0.0.1`, r.Answer[0].String())
			})
		}
	})
}
