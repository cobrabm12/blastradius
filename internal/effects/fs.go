package effects

import (
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() {
	Register("rm", extractRm)
	Register("rmdir", extractRm)
	Register("shred", extractRm)
	Register("mv", extractMv)
	Register("cp", extractCp)
	Register("dd", extractDd)
	Register("truncate", extractTruncate)
	Register("tee", extractTee)
	Register("chmod", extractMetadata)
	Register("chown", extractMetadata)
	Register("ln", extractLn)
	Register("mkdir", extractMkdir)
	Register("touch", extractTouch)

	// sed rewrites its input in place under -i, so it cannot be read-only.
	Register("sed", extractSed)

	// Read-only commands whose operands are paths. Registering them keeps
	// ordinary inspection from tripping on_error, which is what makes the tool
	// bearable day to day.
	for _, name := range []string{
		"cat", "less", "more", "head", "tail", "grep", "rg", "ag", "ls", "stat",
		"file", "wc", "diff", "md5sum", "sha256sum", "awk", "sort", "uniq",
		"which", "basename", "dirname", "realpath", "readlink", "du", "df",
	} {
		Register(name, extractReadOnly)
	}

	// Commands whose operands are not paths at all. Reporting their arguments
	// as reads would invent targets that were never touched.
	for _, name := range []string{
		"echo", "printf", "true", "false", ":", "date", "pwd", "test", "[",
		"sleep", "id", "whoami", "uname", "hostname",
	} {
		Register(name, extractNoPaths)
	}
}

func extractRm(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	flags, targets := operands(inv.Argv)
	for _, t := range targets {
		e.Deletes = append(e.Deletes, paths.Expand(t, ctx)...)
	}
	// Deletion has no undo. Recursion only widens the radius.
	e.Irreversible = len(e.Deletes) > 0
	if flags['r'] {
		e.Notes = append(e.Notes, "recursive delete")
	}
	return e
}

// extractMv: every operand but the last is removed from its old location; the
// last is written.
func extractMv(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	for _, src := range ops[:len(ops)-1] {
		e.Deletes = append(e.Deletes, paths.Expand(src, ctx)...)
	}
	e.Writes = append(e.Writes, paths.Expand(ops[len(ops)-1], ctx)...)
	e.Irreversible = true
	return e
}

// extractCp: sources are read, the destination is written.
func extractCp(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	for _, src := range ops[:len(ops)-1] {
		e.Reads = append(e.Reads, paths.Expand(src, ctx)...)
	}
	e.Writes = append(e.Writes, paths.Expand(ops[len(ops)-1], ctx)...)
	return e
}

// extractDd reads if= and writes of=. Its writes are raw and unrecoverable.
func extractDd(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	for _, a := range inv.Argv[1:] {
		switch {
		case strings.HasPrefix(a, "of="):
			e.Writes = append(e.Writes, paths.Expand(a[3:], ctx)...)
			e.Irreversible = true
		case strings.HasPrefix(a, "if="):
			e.Reads = append(e.Reads, paths.Expand(a[3:], ctx)...)
		}
	}
	if len(e.Writes) == 0 {
		e.Unknown = true
	}
	return e
}

func extractTruncate(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	for _, t := range ops {
		e.Truncates = append(e.Truncates, paths.Expand(t, ctx)...)
	}
	e.Irreversible = len(e.Truncates) > 0
	return e
}

func extractTee(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	flags, ops := operands(inv.Argv)
	for _, t := range ops {
		expanded := paths.Expand(t, ctx)
		if flags['a'] {
			e.Writes = append(e.Writes, expanded...)
		} else {
			e.Truncates = append(e.Truncates, expanded...)
		}
	}
	return e
}

// extractMetadata covers chmod and chown: the file's content survives, but its
// access rules do not, so this counts as a write.
func extractMetadata(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		e.Unknown = true
		return e
	}
	for _, t := range ops[1:] { // the first operand is the mode or owner
		e.Writes = append(e.Writes, paths.Expand(t, ctx)...)
	}
	return e
}

func extractLn(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	if len(ops) == 0 {
		e.Unknown = true
		return e
	}
	e.Writes = append(e.Writes, paths.Expand(ops[len(ops)-1], ctx)...)
	return e
}

func extractMkdir(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	for _, t := range ops {
		e.Writes = append(e.Writes, paths.Expand(t, ctx)...)
	}
	return e
}

func extractTouch(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	for _, t := range ops {
		e.Writes = append(e.Writes, paths.Expand(t, ctx)...)
	}
	return e
}

// extractReadOnly models commands that observe without modifying. Their
// operands are reported as reads so that read-protected paths still apply.
func extractReadOnly(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	_, ops := operands(inv.Argv)
	for _, t := range ops {
		e.Reads = append(e.Reads, paths.Expand(t, ctx)...)
	}
	return e
}

// extractSed reports an in-place edit (-i) as a write, and everything else as a
// read. The first operand of a sed invocation is the script, not a path.
func extractSed(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	inPlace := false
	for _, a := range inv.Argv[1:] {
		if a == "-i" || strings.HasPrefix(a, "-i.") || a == "--in-place" {
			inPlace = true
		}
	}
	_, ops := operands(inv.Argv)
	if len(ops) < 2 {
		// Script only: sed is reading a pipe.
		return e
	}
	for _, t := range ops[1:] {
		expanded := paths.Expand(t, ctx)
		if inPlace {
			e.Writes = append(e.Writes, expanded...)
			e.Irreversible = true
		} else {
			e.Reads = append(e.Reads, expanded...)
		}
	}
	return e
}

// extractNoPaths models commands whose arguments name no filesystem target.
func extractNoPaths(_ shell.Invocation, _ paths.Context) Effects {
	return Effects{}
}
