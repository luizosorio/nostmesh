// Package version exposes build metadata injected at link time.
package version

import "runtime/debug"

// Values injected via -ldflags at build time. They intentionally default to
// placeholders so that a plain "go build" still produces a working binary.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Info describes the running build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
}

// Get returns the build information for this binary. When the linker did not
// inject a commit, it falls back to VCS data embedded by the Go toolchain.
func Get() Info {
	info := Info{
		Version: version,
		Commit:  commit,
		Date:    date,
	}

	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	info.GoVersion = build.GoVersion

	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "unknown" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if info.Date == "unknown" {
				info.Date = setting.Value
			}
		}
	}
	return info
}
