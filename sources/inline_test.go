package sources

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewInlineSource(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		source, err := NewInlineSource(`inline:{"example":{"description":"Description for example", "binaries":["example"], "channel": {"unstable": {"update": "5m", "source": "git@github.com:cashapp/example.git"}}}}`)
		require.NoError(t, err)
		require.NotNil(t, source)
	})
}
