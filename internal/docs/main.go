package main

import (
	"github.com/learn-dns-security-com/gothdns/internal"
	"go.uber.org/zap"
	"os"
)

func main() {
	f, err := os.Create("/app/docs/plugins.md")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	handler := internal.NewRequestHandler(zap.NewNop())

	f.WriteString("This documentation is auto-generated. Each plugin own its part of documentation based on [PluginSelfDescribing](internal/plugin.go) and [RegisteredDNSViolations](internal/plugin.go) interfaces.\n\n")
	for _, p := range handler.Plugins() {
		f.WriteString("## " + p.Name() + "\n")
		if pd, ok := p.(internal.PluginSelfDescribing); ok {
			f.WriteString(pd.Description() + "\n")
			f.WriteString("#### Examples:" + "\n")
			f.WriteString(pd.Examples() + "\n")
		}
		if pv, ok := p.(internal.RegisteredDNSViolations); ok {
			v := pv.DNSViolation()
			f.WriteString("#### DNS Violation: ")
			f.WriteString("[" + v.Identifier + "](" + v.Link + ")\n")
		}
		f.WriteString("\n")
	}
}
