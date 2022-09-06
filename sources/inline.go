package sources

import (
	"strings"

	"github.com/alecthomas/hcl"
	"github.com/cashapp/hermit/errors"
)

const InlineSourcePrefix = "inline:"

var wrongPrefixErr = errors.New("inline uri does not have the right prefix")

// NewInlineSource parsed the uri as a json map from package name to package configuration.
func NewInlineSource(uri string) (MemSource, error) {
	if !strings.HasPrefix(uri, InlineSourcePrefix) {
		return nil, wrongPrefixErr
	}
	contents := uri[len(InlineSourcePrefix):]

	sources := map[string]interface{}{}
	if err := hcl.Unmarshal([]byte(contents), &sources); err != nil {
		return nil, err
	}

	memSources := MemSource{}
	for name, manifest := range sources {
		marshalled, err := hcl.Marshal(manifest)
		if err != nil {
			return nil, err
		}
		memSources[name] = string(marshalled)
	}
	return memSources, nil
}
