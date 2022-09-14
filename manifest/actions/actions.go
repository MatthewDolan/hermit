package actions

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/alecthomas/hcl"
	"github.com/kballard/go-shellquote"

	"github.com/cashapp/hermit/errors"
	"github.com/cashapp/hermit/shell"
	"github.com/cashapp/hermit/vfs"
)

// go-sumtype:decl Action EnvOp

// Package interface type that represents a *resolver.Package.
type Package interface {
	GetFS() fs.FS

	RootDir() string
}

// Action interface implemented by all lifecycle trigger actions.
type Action interface {
	Position() hcl.Position
	Apply(p Package) error
	String() string
}

// MessageAction displays a message to the user.
type MessageAction struct {
	Pos hcl.Position `hcl:"-"`

	Text string `hcl:"text" help:"Message text to display to user."`
}

// Position returns the hcl position of the action.
func (m *MessageAction) Position() hcl.Position { return m.Pos }
func (m *MessageAction) String() string         { return fmt.Sprintf("echo %s", shell.Quote(m.Text)) }
func (m *MessageAction) Apply(p Package) error  { return nil } // nolint

// RenameAction renames a file.
type RenameAction struct {
	Pos hcl.Position `hcl:"-"`

	From string `hcl:"from" help:"Source path to rename."`
	To   string `hcl:"to" help:"Destination path to rename to."`
}

// Position returns the hcl position of the action.
func (r *RenameAction) Position() hcl.Position { return r.Pos }
func (r *RenameAction) String() string {
	return fmt.Sprintf("mv %s %s", shell.Quote(r.From), shell.Quote(r.To))
}
func (r *RenameAction) Apply(Package) error { // nolint
	return os.Rename(r.From, r.To)
}

// DeleteAction deletes files.
type DeleteAction struct {
	Pos       hcl.Position `hcl:"-"`
	Recursive bool         `hcl:"recursive,optional" help:"Recursively delete."`
	Files     []string     `hcl:"files" help:"Files to delete."`
}

// Position returns the hcl position of the action.
func (d *DeleteAction) Position() hcl.Position { return d.Pos }
func (d *DeleteAction) String() string         { return fmt.Sprintf("rm %s", strings.Join(d.Files, " ")) }
func (d *DeleteAction) Apply(Package) error { // nolint
	for _, file := range d.Files {
		if d.Recursive {
			if err := os.RemoveAll(file); err != nil {
				return errors.Wrap(err, file)
			}
		} else if err := os.Remove(file); err != nil {
			return errors.Wrap(err, file)
		}
	}
	return nil
}

// ChmodAction changes the file mode on a file.
type ChmodAction struct {
	Pos hcl.Position `hcl:"-"`

	Mode int    `hcl:"mode" help:"File mode to set."`
	File string `hcl:"file" help:"File to set mode on."`
}

// Position returns the hcl position of the action.
func (c *ChmodAction) Position() hcl.Position { return c.Pos }
func (c *ChmodAction) String() string         { return fmt.Sprintf("chmod %o %s", c.Mode, shell.Quote(c.File)) }
func (c *ChmodAction) Apply(Package) error { // nolint
	return os.Chmod(c.File, os.FileMode(c.Mode))
}

// RunAction executes a command when a lifecycle event occurs
type RunAction struct {
	Pos hcl.Position `hcl:"-"`

	Command string   `hcl:"cmd" help:"The command to execute, split by shellquote."`
	Dir     string   `hcl:"dir,optional" help:"The directory where the command is run. Defaults to the ${root} directory."`
	Args    []string `hcl:"args,optional" help:"The arguments to the binary."`
	Env     []string `hcl:"env,optional" help:"The environment variables for the execution."`
	Stdin   string   `hcl:"stdin,optional" help:"Optional string to be used as the stdin for the command."`
}

// Position returns the hcl position of the action.
func (r *RunAction) Position() hcl.Position { return r.Pos }
func (r *RunAction) String() string {
	return fmt.Sprintf("%s %s", r.Command, shellquote.Join(r.Args...))
}
func (r *RunAction) Apply(p Package) error { // nolint
	args, err := shellquote.Split(r.Command)
	if err != nil {
		return errors.Wrapf(err, "%s: invalid shell command %q", p, r.Command)
	}
	args = append(args, r.Args...)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = r.Env
	if r.Dir == "" {
		cmd.Dir = p.RootDir()
	} else {
		cmd.Dir = r.Dir
	}
	if r.Stdin != "" {
		cmd.Stdin = strings.NewReader(r.Stdin)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "%s: failed to execute %q: %s", p, r.Command, string(out))
	}
	return nil
}

// CopyAction is an action for copying
type CopyAction struct {
	Pos hcl.Position `hcl:"-"`

	From string      `hcl:"from" help:"The source file to copy from. Absolute paths reference the file system while relative paths are against the manifest source bundle."`
	To   string      `hcl:"to" help:"The relative destination to copy to, based on the context."`
	Mode os.FileMode `hcl:"mode,optional" help:"File mode of file."`
}

// Position returns the hcl position of the action.
func (c *CopyAction) Position() hcl.Position { return c.Pos }
func (c *CopyAction) String() string {
	mode := c.Mode
	if mode == 0 {
		mode = 0600
	}
	return fmt.Sprintf("install -m %04o %s %s", mode, shell.Quote(c.From), shell.Quote(c.To))
}
func (c *CopyAction) Apply(p Package) error { // nolint
	fromFS := p.GetFS()
	if filepath.IsAbs(c.From) {
		fromFS = os.DirFS("/")
	}
	if err := vfs.CopyFile(fromFS, c.From, c.To); err != nil {
		return errors.WithStack(err)
	}
	// Use source file mode unless overridden.
	mode := c.Mode
	if c.Mode == 0 {
		info, err := fs.Stat(fromFS, c.From)
		if err == nil {
			mode = info.Mode()
		}
	}
	return os.Chmod(c.To, mode)
}
