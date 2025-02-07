package markdown

import (
	"github.com/learn-dns-security-com/gothdns/internal"
	"github.com/learn-dns-security-com/gothdns/internal/markdowntest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"strings"
	"testing"
)

func TestGenerator_Run(t *testing.T) {
	t.Run("mocked plugins", func(t *testing.T) {
		generator := new(Generator)
		txt, err := generator.Run([]internal.Plugin{
			new(markdowntest.SimplePlugin),
			new(markdowntest.PluginWithDescription),
			new(markdowntest.PluginWithDescriptionAndViolation),
		})
		require.NoError(t, err)
		assert.Equal(t, `This documentation is auto-generated. Each plugin own its part of documentation based on [PluginSelfDescribing](internal/plugin.go) and [RegisteredDNSViolations](internal/plugin.go) interfaces.


## module-1
No description available yet


## module-2
this is a description


#### Examples
this is an example


## module-3
this is another description


#### Examples
this is another example

#### DNS Violation: [abc](https://learn-dns-security.com/)`, txt)
	})

	t.Run("all plugins", func(t *testing.T) {
		handler := internal.NewRequestHandler(zap.NewNop())
		plugins := handler.Plugins()

		generator := new(Generator)
		txt, err := generator.Run(plugins)
		require.NoError(t, err)

		assert.Equal(t, len(plugins), strings.Count(txt, "\n## "))
	})
}
