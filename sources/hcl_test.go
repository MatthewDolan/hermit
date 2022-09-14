package sources

import (
	"io/fs"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHCLSource(t *testing.T) {
	source, err := NewHCLSource([]byte(`
package "foo" {
  description = "Description for foo"
  binaries = ["foo"]
  channel "unstable" {
    update = "5m0s"
    source = "git@github.com:cashapp/foo.git"
  }
}

package "bar" {
  description = "Description for bar"
  binaries = ["bar"]
  channel "unstable" {
    update = "5m0s"
    source = "git@github.com:cashapp/bar.git"
  }
}
`))
	require.NoError(t, err)

	bundle := source.Bundle()

	matches, err := fs.Glob(bundle, "*.hcl")
	require.NoError(t, err)
	require.Len(t, matches, 2)

	actualFoo, err := fs.ReadFile(bundle, "foo.hcl")
	require.NoError(t, err)
	require.Equal(t, `binaries = ["foo"]
description = "Description for foo"

channel "unstable" {
  update = "5m0s"
  source = "git@github.com:cashapp/foo.git"
}
`, string(actualFoo))

	acutalBar, err := fs.ReadFile(bundle, "bar.hcl")
	require.NoError(t, err)
	require.Equal(t, `binaries = ["bar"]
description = "Description for bar"

channel "unstable" {
  update = "5m0s"
  source = "git@github.com:cashapp/bar.git"
}
`, string(acutalBar))
}
