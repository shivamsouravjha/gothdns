package markdown

import (
	"bytes"
	"github.com/learn-dns-security-com/gothdns/internal"
	"text/template"
)

type Generator struct{}

type PluginDoc struct {
	Name          string
	Description   string
	Examples      string
	ViolationID   string
	ViolationLink string
}

func (g *Generator) Run(plugins []internal.Plugin) (string, error) {
	var pd []PluginDoc
	for _, p := range plugins {
		d := PluginDoc{
			Name: p.Name(),
		}
		if sd, ok := p.(internal.PluginSelfDescribing); ok {
			d.Description = sd.Description()
			d.Examples = sd.Examples()
		}
		if sv, ok := p.(internal.RegisteredDNSViolations); ok {
			v := sv.DNSViolation()
			d.ViolationID = v.Identifier
			d.ViolationLink = v.Link
		}

		pd = append(pd, d)
	}

	var buf bytes.Buffer

	tmpl, err := template.New("doc.tmpl").ParseFiles("/app/internal/markdown/doc.tmpl")
	if err != nil {
		return "", err
	}
	err = tmpl.Execute(&buf, pd)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
