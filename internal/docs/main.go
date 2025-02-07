package main

import (
	"github.com/learn-dns-security-com/gothdns/internal"
	"github.com/learn-dns-security-com/gothdns/internal/markdown"
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
	plugins := handler.Plugins()

	generator := new(markdown.Generator)
	txt, err := generator.Run(plugins)
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile("/app/docs/plugins.md", []byte(txt), 0644); err != nil {
		panic(err)
	}
}
