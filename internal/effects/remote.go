package effects

import (
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() {
	Register("ssh", extractSSH)
	Register("scp", extractTransfer)
	Register("rsync", extractTransfer)
	Register("psql", extractSQL)
	Register("mysql", extractSQL)
	Register("docker", extractDocker)
	Register("pm2", extractPM2)
	Register("systemctl", extractSystemctl)
}

// hostOf strips a user@ prefix and any :path suffix from a remote spec.
// The bool reports whether the argument names a remote at all.
func hostOf(arg string) (string, bool) {
	if i := strings.Index(arg, ":"); i >= 0 {
		arg = arg[:i]
	} else if !strings.Contains(arg, "@") {
		return "", false
	}
	if i := strings.Index(arg, "@"); i >= 0 {
		arg = arg[i+1:]
	}
	if arg == "" {
		return "", false
	}
	return arg, true
}

func extractSSH(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) == 0 {
		e.Unknown = true
		return e
	}
	host := ops[0]
	if i := strings.Index(host, "@"); i >= 0 {
		host = host[i+1:]
	}
	e.Remotes = append(e.Remotes, Remote{Host: host, Verb: VerbExec})
	if len(ops) > 1 {
		// The remote command is not analyzed: it runs under a different
		// filesystem and policy than the one we hold.
		e.Unknown = true
		e.Notes = append(e.Notes, "remote command not analyzed: "+strings.Join(ops[1:], " "))
	}
	return e
}

// extractTransfer covers scp and rsync: a remote source is a read, a remote
// destination is a write.
func extractTransfer(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	dst := ops[len(ops)-1]
	if host, ok := hostOf(dst); ok {
		e.Remotes = append(e.Remotes, Remote{Host: host, Verb: VerbWrite})
	} else {
		e.Writes = append(e.Writes, paths.Expand(dst, ctx)...)
	}
	for _, src := range ops[:len(ops)-1] {
		if host, ok := hostOf(src); ok {
			e.Remotes = append(e.Remotes, Remote{Host: host, Verb: VerbRead})
		} else {
			e.Reads = append(e.Reads, paths.Expand(src, ctx)...)
		}
	}
	return e
}

// destructiveSQL lists statement keywords that discard data.
var destructiveSQL = []string{"drop ", "truncate ", "delete "}

func extractSQL(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	host := ""
	sql := ""
	for i := 1; i < len(inv.Argv); i++ {
		switch inv.Argv[i] {
		case "-h", "--host":
			if i+1 < len(inv.Argv) {
				host = inv.Argv[i+1]
			}
		case "-c", "--command", "-e":
			if i+1 < len(inv.Argv) {
				sql = inv.Argv[i+1]
			}
		}
	}
	if host == "" {
		host = "localhost"
	}

	verb := VerbWrite
	lower := strings.ToLower(strings.TrimSpace(sql))
	switch {
	case sql == "":
		e.Unknown = true
		e.Notes = append(e.Notes, "SQL not given on the command line")
	case strings.HasPrefix(lower, "select"), strings.HasPrefix(lower, "explain"),
		strings.HasPrefix(lower, "show"), strings.HasPrefix(lower, "\\d"):
		verb = VerbRead
	default:
		for _, d := range destructiveSQL {
			if strings.Contains(lower, d) {
				e.Irreversible = true
			}
		}
	}
	e.Remotes = append(e.Remotes, Remote{Host: host, Verb: verb})
	return e
}

func extractDocker(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	for i := 1; i < len(inv.Argv); i++ {
		if (inv.Argv[i] == "-H" || inv.Argv[i] == "--host") && i+1 < len(inv.Argv) {
			e.Remotes = append(e.Remotes, Remote{Host: inv.Argv[i+1], Verb: VerbExec})
		}
	}
	_, ops := operands(inv.Argv)
	if len(ops) > 0 {
		switch ops[0] {
		case "rm", "rmi", "prune", "kill", "down":
			e.Irreversible = true
		}
	}
	e.Notes = append(e.Notes, "docker: effects inside containers are not modeled")
	e.Unknown = true
	return e
}

func extractPM2(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) > 0 && (ops[0] == "delete" || ops[0] == "kill") {
		e.Irreversible = true
	}
	e.Notes = append(e.Notes, "pm2: process effects are not modeled")
	return e
}

func extractSystemctl(inv shell.Invocation, _ paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) > 0 {
		switch ops[0] {
		case "status", "show", "list-units", "is-active", "cat":
			return e
		}
	}
	e.Notes = append(e.Notes, "systemctl: service state changes are not modeled")
	return e
}
