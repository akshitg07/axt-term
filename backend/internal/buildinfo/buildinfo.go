// Package buildinfo exposes version metadata stamped in at link time.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Overridden with -ldflags at build time. See the Makefile.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info describes the running build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the build metadata, falling back to the VCS stamp the Go
// toolchain embeds when ldflags were not supplied (a plain `go build`).
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if info.Commit == "" || info.BuildDate == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				switch s.Key {
				case "vcs.revision":
					if info.Commit == "" {
						info.Commit = s.Value
					}
				case "vcs.time":
					if info.BuildDate == "" {
						info.BuildDate = s.Value
					}
				}
			}
		}
	}
	return info
}

// String renders a one-line summary for logs.
func (i Info) String() string {
	s := i.Version
	if i.Commit != "" {
		commit := i.Commit
		if len(commit) > 8 {
			commit = commit[:8]
		}
		s += " (" + commit + ")"
	}
	return s
}
