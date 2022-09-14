package sources

import (
	"github.com/alecthomas/hcl"

	"github.com/cashapp/hermit/errors"
	"github.com/cashapp/hermit/manifest"
)

// NewHCLSource parses the source HCL and returns a MemSource with the packages.
func NewHCLSource(sourcesHCL []byte) (MemSource, error) {
	var manifests manifest.Manifests
	if err := hcl.Unmarshal(sourcesHCL, &manifests); err != nil {
		return nil, errors.Wrap(err, "unable to unmarshall sources hcl")
	}

	memSource := MemSource{}
	for _, p := range manifests.Packages {
		manifestHCL, err := hcl.Marshal(&p.Manifest)
		if err != nil {
			return nil, errors.Wrap(err, "unable to marshall manifest hcl")
		}
		memSource[p.Name+".hcl"] = string(manifestHCL)
	}
	return memSource, nil
}
