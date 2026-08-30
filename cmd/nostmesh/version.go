package main

import (
	"encoding/json"
	"flag"

	"github.com/luizosorio/nostmesh/internal/version"
)

func runVersion(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr.w)
	asJSON := flags.Bool("json", false, "print build information as JSON")

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh version [--json]\n\nPrint build information.\n\nFlags:\n")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}
	if flags.NArg() > 0 {
		stderr.printf("nostmesh version: unexpected argument %q\n", flags.Arg(0))
		return exitUsage
	}

	info := version.Get()

	if *asJSON {
		encoded, err := json.Marshal(info)
		if err != nil {
			stderr.printf("nostmesh version: %v\n", err)
			return exitError
		}
		stdout.printf("%s\n", encoded)
		return exitOK
	}

	stdout.printf("nostmesh %s\n", info.Version)
	stdout.printf("  commit: %s\n", info.Commit)
	stdout.printf("  built:  %s\n", info.Date)
	stdout.printf("  go:     %s\n", info.GoVersion)

	return exitOK
}
