package config

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		port := os.Getenv("PORT")

		err := os.Setenv("PORT", "1234")
		require.NoError(t, err)

		defer func() {
			err := os.Setenv("PORT", port)
			require.NoError(t, err)
		}()

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, 1234, cfg.Port)
	})

	t.Run("invalid config", func(t *testing.T) {
		port := os.Getenv("PORT")

		err := os.Setenv("PORT", "foo")
		require.NoError(t, err)

		defer func() {
			err := os.Setenv("PORT", port)
			require.NoError(t, err)
		}()

		_, err = Load()
		require.Error(t, err)
	})
}
