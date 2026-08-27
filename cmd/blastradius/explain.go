package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/engine"
	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

func runExplain(args []string) error {
	if len(args) == 0 {
		return errors.New(`usage: blastradius explain "<command>"`)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	pol, err := loadPolicy(cwd)
	if err != nil {
		return err
	}
	v := engine.Analyze(engine.Request{
		Command: args[0],
		Ctx:     context(cwd),
		Policy:  pol,
	})
	renderVerdict(v, os.Stdout)
	if v.Decision == policy.Block {
		os.Exit(1)
	}
	return nil
}

// renderVerdict writes a human-readable account of what a command touches and
// which rule decided its fate.
func renderVerdict(v policy.Verdict, w io.Writer) {
	fmt.Fprintf(w, "%s  (%s)\n", decisionLabel(v.Decision), v.Rule)
	fmt.Fprintf(w, "  reason: %s\n", v.Reason)

	fmt.Fprintln(w, "\n  blast radius:")
	printed := false
	for _, group := range []struct {
		verb effects.Verb
		list []paths.Path
	}{
		{effects.VerbDelete, v.Radius.Deletes},
		{effects.VerbTruncate, v.Radius.Truncates},
		{effects.VerbWrite, v.Radius.Writes},
		{effects.VerbRead, v.Radius.Reads},
	} {
		for _, p := range group.list {
			printed = true
			switch {
			case !p.Resolved:
				fmt.Fprintf(w, "    %-9s %s  [unresolved]\n", group.verb, displayRaw(p))
			case p.IsGlob:
				fmt.Fprintf(w, "    %-9s %s  [glob]\n", group.verb, p.Abs)
			default:
				fmt.Fprintf(w, "    %-9s %s\n", group.verb, p.Abs)
			}
		}
	}
	for _, r := range v.Radius.Remotes {
		printed = true
		fmt.Fprintf(w, "    %-9s %s  [remote]\n", r.Verb, r.Host)
	}
	if !printed {
		fmt.Fprintln(w, "    (nothing detected)")
	}

	if v.Radius.Irreversible {
		fmt.Fprintln(w, "\n  irreversible: yes")
	}
	if v.Radius.Unknown {
		fmt.Fprintln(w, "  analysis incomplete: yes")
	}
	for _, n := range v.Radius.Notes {
		fmt.Fprintf(w, "  note: %s\n", n)
	}
}

// displayRaw renders an unresolved path, substituting a readable placeholder
// for the sentinel the parser uses internally.
func displayRaw(p paths.Path) string {
	if p.Raw == "" || p.Raw[0] == '\x00' {
		return "<computed at runtime>"
	}
	return p.Raw
}

func decisionLabel(d policy.Decision) string {
	switch d {
	case policy.Block:
		return "BLOCK"
	case policy.Ask:
		return "ASK"
	default:
		return "ALLOW"
	}
}
