package internal

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/miekg/dns"
)

type Plugin interface {
	Reply(m *dns.Msg) []byte
	Name() string
}

type PluginSelfDescribing interface {
	Description() string
	Examples() string
}

type RegisteredDNSViolations interface {
	DNSViolation() plugin.Violation
}
