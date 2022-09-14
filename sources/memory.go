package sources

import (
	"fmt"
	"io/fs"

	"github.com/cashapp/hermit/ui"
	"github.com/cashapp/hermit/vfs"
)

// MemSource is a new Source based on a name and content kept in memory
type MemSource map[string]string

// NewMemSource returns a new MemSource
func NewMemSource(name, content string) MemSource {
	return MemSource{name: content}
}

func (s MemSource) Sync(_ *ui.UI, _ bool) error { // nolint: golint
	return nil
}

func (s MemSource) URI() string { // nolint: golint
	var names []string
	for name := range s {
		names = append(names, name)
	}
	if len(names) == 1 {
		return names[0]
	}
	return fmt.Sprintf("%s", names)
}

func (s MemSource) Bundle() fs.FS { // nolint: golint
	return vfs.InMemoryFS(s)
}
