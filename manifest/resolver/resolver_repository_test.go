package resolver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cashapp/hermit/manifest"
)

func TestInferRepository(t *testing.T) {
	tests := []struct {
		name               string
		Package            *Package
		expectedRepository string
		Manifest           *manifest.Manifest
	}{
		{
			name:               "empty repository on no source",
			Package:            &Package{},
			expectedRepository: "",
		},
		{
			name:               "not changing repository on exists",
			Package:            &Package{Repository: "https://github.com/cashapp/hermit-packages", Source: "https://github.com/bpkg/bpkg/archive/refs/tags/${version}.tar.gz"},
			expectedRepository: "https://github.com/cashapp/hermit-packages",
		},
		{
			name:               "only able to infer repository from github com",
			Package:            &Package{Source: "https://awscli.amazonaws.com/AWSCLIV2-2.5.0.pkg"},
			expectedRepository: "",
		},
		{
			name:               "not inferring from https://github.com/cashapp/hermit-build",
			Package:            &Package{Source: "https://github.com/cashapp/hermit-build/releases/download/bash/bash-4.3.0-osx-arm64.xz"},
			expectedRepository: "",
		},
		{
			name:               "infer github.com repository from source",
			Package:            &Package{Source: "https://github.com/bpkg/bpkg/archive/refs/tags/${version}.tar.gz"},
			expectedRepository: "https://github.com/bpkg/bpkg",
		},
		{
			name:    "able to figure out from manifest from github auto version",
			Package: &Package{Source: "git@github.com:cashapp/test-project.git#v${version"},
			Manifest: &manifest.Manifest{
				Versions: []manifest.VersionBlock{
					{
						Version: nil,
						AutoVersion: &manifest.AutoVersionBlock{
							GitHubRelease: "cashapp/test-project",
						},
					},
				},
			},
			expectedRepository: "https://github.com/cashapp/test-project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inferPackageRepository(tt.Package, tt.Manifest)

			require.Equal(t, tt.Package.Repository, tt.expectedRepository)
		})
	}
}
