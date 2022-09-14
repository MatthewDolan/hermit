package manifesttest

import (
	"io/fs"
	"time"

	"github.com/cashapp/hermit/envars"
	"github.com/cashapp/hermit/manifest"
	"github.com/cashapp/hermit/manifest/actions"
	"github.com/cashapp/hermit/manifest/resolver"
	"github.com/cashapp/hermit/platform"
)

// PkgBuilder is a builder pattern implementation for manifest.Package objects
type PkgBuilder struct {
	result *resolver.Package
}

// NewPkgBuilder returns a new builder with sensible default values
func NewPkgBuilder(root string) PkgBuilder {
	ref := manifest.Reference{
		Name:    "test",
		Version: manifest.Version{},
	}
	return PkgBuilder{
		&resolver.Package{
			Reference: ref,
			Binaries:  []string{"darwin_exe", "linux_exe"},
			Root:      root,
			Dest:      root,
			Triggers:  map[actions.Event][]actions.Action{},
			State:     manifest.PackageStateRemote,
			Files:     []*resolver.ResolvedFileRef{},
		},
	}
}

// Result returns the manifest.Package object
func (b PkgBuilder) Result() *resolver.Package {
	return b.result
}

// WithName sets the name of the package
func (b PkgBuilder) WithName(name string) PkgBuilder {
	b.result.Reference.Name = name
	return b
}

// WithVersion sets the version of the package
func (b PkgBuilder) WithVersion(version string) PkgBuilder {
	b.result.Reference.Version = manifest.ParseVersion(version)
	return b
}

// WithChannel sets the the channel of the package
func (b PkgBuilder) WithChannel(name string) PkgBuilder {
	b.result.Reference.Channel = name
	return b
}

// WithDest sets the destination of the package
func (b PkgBuilder) WithDest(dst string) PkgBuilder {
	b.result.Dest = dst
	return b
}

// WithBinaries sets the name of the binaries in the package
func (b PkgBuilder) WithBinaries(bins ...string) PkgBuilder {
	b.result.Binaries = bins
	return b
}

// WithSource sets the source of the package
func (b PkgBuilder) WithSource(src string) PkgBuilder {
	b.result.Source = src
	return b
}

// WithWarnings sets the warnings in the package
func (b PkgBuilder) WithWarnings(warnings ...string) PkgBuilder {
	b.result.Warnings = warnings
	return b
}

// WithSHA256 sets the sha256 hash of the package
func (b PkgBuilder) WithSHA256(sha string) PkgBuilder {
	b.result.SHA256 = sha
	return b
}

// WithUpdateInterval sets the update interval for the package
func (b PkgBuilder) WithUpdateInterval(dur time.Duration) PkgBuilder {
	b.result.UpdateInterval = dur
	return b
}

// WithFile adds an external file to the package
func (b PkgBuilder) WithFile(src, dst string, fs fs.FS) PkgBuilder {
	b.result.Files = append(b.result.Files, &resolver.ResolvedFileRef{
		FS:       fs,
		FromPath: src,
		ToPAth:   dst,
	})
	return b
}

// WithTrigger adds a lifecycle trigger to the package
func (b PkgBuilder) WithTrigger(event actions.Event, actions ...actions.Action) PkgBuilder {
	b.result.Triggers[event] = append(b.result.Triggers[event], actions...)
	return b
}

// WithEnvOps adds Ops to the package.
func (b PkgBuilder) WithEnvOps(ops ...envars.Op) PkgBuilder {
	b.result.Env = append(b.result.Env, ops...)
	return b
}

// WithFS sets the manifest source FS for this package.
func (b PkgBuilder) WithFS(fs fs.FS) PkgBuilder {
	b.result.FS = fs
	return b
}

// WithRequires sets the required dependencies
func (b PkgBuilder) WithRequires(reqs ...string) PkgBuilder {
	b.result.Requires = reqs
	return b
}

// WithProvides sets the virtual packages this package provides
func (b PkgBuilder) WithProvides(provs ...string) PkgBuilder {
	b.result.Provides = provs
	return b
}

// WithUnsupportedPlatforms sets the unsupported platforms for the package
func (b PkgBuilder) WithUnsupportedPlatforms(platforms []platform.Platform) PkgBuilder {
	b.result.UnsupportedPlatforms = platforms
	return b
}
