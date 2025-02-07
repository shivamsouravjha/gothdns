package markdowntest

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/miekg/dns"
)

type SimplePlugin struct{}

func (p *SimplePlugin) Reply(m *dns.Msg) []byte {
	return nil
}

func (p *SimplePlugin) Name() string {
	return "module-1"
}

type PluginWithDescription struct{}

func (p *PluginWithDescription) Reply(m *dns.Msg) []byte {
	return nil
}

func (p *PluginWithDescription) Name() string {
	return "module-2"
}

func (p *PluginWithDescription) Description() string {
	return "this is a description"
}

func (p *PluginWithDescription) Examples() string {
	return "this is an example"
}

type PluginWithDescriptionAndViolation struct{}

func (p *PluginWithDescriptionAndViolation) Reply(m *dns.Msg) []byte {
	return nil
}

func (p *PluginWithDescriptionAndViolation) Name() string {
	return "module-3"
}

func (p *PluginWithDescriptionAndViolation) Description() string {
	return "this is another description"
}

func (p *PluginWithDescriptionAndViolation) Examples() string {
	return "this is another example"
}

func (p *PluginWithDescriptionAndViolation) DNSViolation() plugin.Violation {
	return plugin.Violation{
		Identifier: "abc",
		Link:       "https://learn-dns-security.com/",
	}
}
