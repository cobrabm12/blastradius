package effects

import (
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() { Register("git", extractGit) }

// extractGit models the git subcommands that destroy work. Everything else is
// reported as a read of the working tree.
func extractGit(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	tree := paths.Expand(".", ctx)

	sub := ""
	var rest []string
	for _, a := range inv.Argv[1:] {
		if sub == "" && a != "" && !strings.HasPrefix(a, "-") {
			sub = a
			continue
		}
		rest = append(rest, a)
	}

	switch sub {
	case "clean":
		e.Deletes = append(e.Deletes, tree...)
		e.Irreversible = true
		e.Notes = append(e.Notes, "git:clean")
	case "reset":
		if hasArg(rest, "--hard") {
			e.Writes = append(e.Writes, tree...)
			e.Irreversible = true
			e.Notes = append(e.Notes, "git:reset --hard")
		} else {
			e.Reads = append(e.Reads, tree...)
		}
	case "push":
		if hasArg(rest, "--force") || hasArg(rest, "-f") || hasArg(rest, "--force-with-lease") {
			e.Irreversible = true
			e.Notes = append(e.Notes, "git:push --force")
		}
		e.Notes = append(e.Notes, "git:push:"+branchOf(rest))
	case "checkout", "switch", "restore":
		e.Writes = append(e.Writes, tree...)
		e.Notes = append(e.Notes, "git:"+sub)
	case "filter-branch", "gc":
		e.Writes = append(e.Writes, tree...)
		e.Irreversible = true
		e.Notes = append(e.Notes, "git:"+sub)
	default:
		e.Reads = append(e.Reads, tree...)
	}
	return e
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// branchOf returns the last non-flag operand, which for `git push <remote>
// <branch>` is the branch. Empty when none is given.
func branchOf(args []string) string {
	last := ""
	for _, a := range args {
		if a != "" && !strings.HasPrefix(a, "-") {
			last = a
		}
	}
	return last
}
