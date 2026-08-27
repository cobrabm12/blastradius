// Package paths resolves the strings a command names into absolute paths.
//
// Resolution is pure: it consults the supplied Context, never the filesystem.
// Anything it cannot resolve is returned with Resolved false, which the policy
// layer treats as unknown rather than as safe.
package paths

import (
	"path"
	"strings"

	"github.com/cobrabm12/blastradius/internal/shell"
)

// Path is one filesystem target named by a command.
type Path struct {
	Raw      string // as written in the command
	Abs      string // absolute; a glob pattern when IsGlob
	Resolved bool   // false when the value could not be determined from source
	IsGlob   bool   // contains wildcard metacharacters, left unexpanded
}

// Context is the environment a command runs in.
type Context struct {
	Cwd  string
	Home string
	Env  map[string]string
}

// Expand resolves one word into the paths it names. Brace expansion can yield
// several; everything else yields exactly one.
//
// Variables are substituted before braces are expanded, because ${NAME} would
// otherwise be mistaken for a brace group.
func Expand(raw string, ctx Context) []Path {
	if raw == shell.Unresolvable || raw == "" {
		return []Path{{Raw: raw, Resolved: false}}
	}
	substituted, ok := substituteVars(raw, ctx.Env)
	if !ok {
		return []Path{{Raw: raw, Resolved: false}}
	}
	var out []Path
	for _, branch := range expandBraces(substituted) {
		out = append(out, resolveOne(branch, raw, ctx))
	}
	return out
}

func resolveOne(s, raw string, ctx Context) Path {
	if s == "~" {
		s = ctx.Home
	} else if strings.HasPrefix(s, "~/") {
		s = path.Join(ctx.Home, s[2:])
	}
	isGlob := strings.ContainsAny(s, "*?[")
	if !isAbs(s) {
		s = path.Join(ctx.Cwd, s)
	} else {
		s = path.Clean(s)
	}
	return Path{Raw: raw, Abs: s, Resolved: true, IsGlob: isGlob}
}

// isAbs reports whether a path is absolute in POSIX terms.
//
// The package deliberately uses slash semantics rather than the host's, because
// what it analyzes is a shell command: those carry POSIX paths whether the
// analyzer runs on Linux, macOS, or Windows under WSL or git-bash. Using
// path/filepath here would make a verdict depend on the operating system of the
// machine doing the analysis, which is exactly the kind of nondeterminism this
// project exists to avoid.
func isAbs(s string) bool { return strings.HasPrefix(s, "/") }

// substituteVars replaces ${NAME} references. The bool reports whether every
// reference was known.
func substituteVars(s string, env map[string]string) (string, bool) {
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			return s, true
		}
		end := strings.Index(s[start:], "}")
		if end < 0 {
			return s, false
		}
		end += start
		name := s[start+2 : end]
		val, ok := env[name]
		if !ok {
			return s, false
		}
		s = s[:start] + val + s[end+1:]
	}
}

// expandBraces performs brace expansion: /a/{x,y}/z yields two paths.
func expandBraces(s string) []string {
	open := strings.Index(s, "{")
	if open < 0 {
		return []string{s}
	}
	closing := strings.Index(s[open:], "}")
	if closing < 0 {
		return []string{s}
	}
	closing += open
	prefix, suffix := s[:open], s[closing+1:]
	var out []string
	for _, alt := range strings.Split(s[open+1:closing], ",") {
		out = append(out, expandBraces(prefix+alt+suffix)...)
	}
	return out
}
