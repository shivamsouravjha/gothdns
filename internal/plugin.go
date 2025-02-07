package internal

import (
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin"
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
