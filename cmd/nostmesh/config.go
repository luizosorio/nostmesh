package main

import (
	"flag"

	"github.com/luizosorio/nostmesh/internal/config"
)

func runConfig(args []string, stdout, stderr *output) int {
	if len(args) == 0 {
		configUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "validate":
		return runConfigValidate(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		configUsage(stdout)
		return exitOK
	default:
		stderr.printf("nostmesh config: unknown subcommand %q\n\n", args[0])
		configUsage(stderr)
		return exitUsage
	}
}

func configUsage(out *output) {
	out.printf("Usage: nostmesh config <subcommand>\n\nSubcommands:\n")
	out.printf("  validate   Check a configuration file and report every problem\n")
}

func runConfigValidate(args []string, stdout, stderr *output) int {
	flags := flag.NewFlagSet("config validate", flag.ContinueOnError)
	flags.SetOutput(stderr.w)

	flags.Usage = func() {
		stderr.printf("Usage: nostmesh config validate <path>\n\n" +
			"Check a configuration file. Reports every problem found, not just\n" +
			"the first, and exits non-zero if the file cannot be used.\n")
	}

	if err := flags.Parse(args); err != nil {
		return exitUsage
	}

	switch flags.NArg() {
	case 0:
		stderr.printf("nostmesh config validate: missing path to the configuration file\n")
		return exitUsage
	case 1:
	default:
		stderr.printf("nostmesh config validate: expected one path, got %d\n", flags.NArg())
		return exitUsage
	}

	path := flags.Arg(0)

	if _, err := config.Load(path); err != nil {
		stderr.printf("%v\n", err)
		return exitError
	}

	stdout.printf("%s: configuration is valid\n", path)
	return exitOK
}
