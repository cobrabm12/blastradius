// Command blastradius computes what a shell command destroys and whether
// policy permits it.
package main

import (
	"fmt"
	"os"
)

// version is set at build time by goreleaser.
var version = "dev"

const usage = `blastradius — deterministic guardrails for coding agents

Usage:
  blastradius explain "<command>"   Show the blast radius and verdict for a command
  blastradius check --agent=<name>  Hook entrypoint; reads a tool call on stdin
  blastradius init                  Generate guard.yaml from this repository
  blastradius install [--shim]      Wire blastradius into the agents found here
  blastradius doctor                Report the enforcement mode and residual gaps
  blastradius allow-once "<cmd>"    Grant a single five-minute exception
  blastradius log [-n N]            Read the audit trail
  blastradius version               Print the version

Policy lives in guard.yaml, in the repository root or ~/.config/blastradius/.
Documentation: https://github.com/cobrabm12/blastradius
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "explain":
		err = runExplain(os.Args[2:])
	case "check":
		err = runCheck(os.Args[2:])
	case "init":
		err = runInit(os.Args[2:])
	case "install":
		err = runInstall(os.Args[2:])
	case "doctor":
		err = runDoctor(os.Args[2:])
	case "allow-once":
		err = runAllowOnce(os.Args[2:])
	case "log":
		err = runLog(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("blastradius", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "blastradius: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "blastradius:", err)
		os.Exit(1)
	}
}
