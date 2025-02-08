package main

import (
	"context"
	"github.com/learn-dns-security-com/gothdns/internal/config"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestMainFunction(t *testing.T) {
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			go main()

			// let the server start
			time.Sleep(time.Millisecond * 200)

			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn("staticip.foo.com"), dns.TypeA)

			c := new(dns.Client)
			c.Net = protocol
			r, _, err := c.Exchange(msg, "127.0.0.1:53")
			require.NoError(t, err)

			require.Equal(t, dns.RcodeSuccess, r.Rcode)
			require.Equal(t, 1, len(r.Answer))
			require.Equal(t, `staticip.foo.com.	60	IN	A	127.0.0.1`, r.Answer[0].String())

			p, err := os.FindProcess(os.Getpid())
			require.NoError(t, err)

			err = p.Signal(syscall.SIGINT)
			require.NoError(t, err)
		})
	}
}

func TestRun(t *testing.T) {
	t.Run("call module", func(t *testing.T) {
		for _, protocol := range []string{"udp", "tcp"} {
			t.Run(protocol, func(t *testing.T) {
				defer goleak.VerifyNone(t)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				logger := zap.NewNop()

				go Run(ctx, logger, config.Environment{
					Addr: "127.0.0.1",
					Port: 10053,
				})

				// let the server start
				time.Sleep(time.Millisecond * 200)

				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn("staticip.foo.com"), dns.TypeA)

				c := new(dns.Client)
				c.Net = protocol
				r, _, err := c.Exchange(m, "127.0.0.1:10053")
				require.NoError(t, err)

				require.Equal(t, dns.RcodeSuccess, r.Rcode)
				require.Equal(t, 1, len(r.Answer))
				require.Equal(t, `staticip.foo.com.	60	IN	A	127.0.0.1`, r.Answer[0].String())
			})
		}
	})
}
