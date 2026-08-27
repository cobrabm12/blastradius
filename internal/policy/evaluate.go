package policy

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
)

// Verdict is a decision together with the rule that produced it. A verdict
// without provenance is a bug.
type Verdict struct {
	Decision Decision
	Reason   string
	Rule     string
	Radius   effects.Effects
}

// Evaluate matches a blast radius against a policy.
//
// Within one target and verb, the last matching rule decides. Across the whole
// radius, the most severe decision wins.
func Evaluate(e effects.Effects, p *Policy) Verdict {
	best := Verdict{Decision: Allow, Rule: "default", Reason: "no rule matched"}

	consider := func(v Verdict) {
		if severity(v.Decision) > severity(best.Decision) {
			best = v
		}
	}

	for _, pair := range pathPairs(e) {
		if !pair.path.Resolved {
			consider(Verdict{
				Decision: p.OnError,
				Rule:     "on_error",
				Reason:   "path could not be resolved: " + pair.path.Raw,
			})
			continue
		}
		consider(match(p.Paths, "paths", pair.path.Abs, pair.verb))
	}

	for _, r := range e.Remotes {
		consider(match(p.Hosts, "hosts", r.Host, r.Verb))
	}

	consider(evaluateGit(e, p))

	if e.Unknown {
		consider(Verdict{
			Decision: p.OnError,
			Rule:     "on_error",
			Reason:   "analysis could not complete",
		})
	}

	best.Radius = e
	return best
}

type pathVerb struct {
	path paths.Path
	verb effects.Verb
}

func pathPairs(e effects.Effects) []pathVerb {
	var out []pathVerb
	for _, group := range []struct {
		list []paths.Path
		verb effects.Verb
	}{
		{e.Deletes, effects.VerbDelete},
		{e.Truncates, effects.VerbTruncate},
		{e.Writes, effects.VerbWrite},
		{e.Reads, effects.VerbRead},
	} {
		for _, p := range group.list {
			out = append(out, pathVerb{path: p, verb: group.verb})
		}
	}
	return out
}

// match applies last-match-wins over ordered rules for one target and verb.
//
// A target that is itself a glob — `rm *.db`, where the shell has not yet
// expanded the pattern — is additionally checked against rules that cover the
// directory it lives in. That widening may only ever tighten the verdict: a
// permissive rule never gets to grant an exception to files nobody has
// enumerated yet, because doing so would let an unrelated `allow` rule at the
// bottom of a policy quietly cancel every protection above it.
func match(rules []Rule, section, target string, verb effects.Verb) Verdict {
	out := Verdict{Decision: Allow, Rule: "default", Reason: "no rule matched"}

	verdictFor := func(i int, r Rule, d Decision) Verdict {
		reason := r.Reason
		if reason == "" {
			reason = fmt.Sprintf("policy says %s %s on %s", d, verb, target)
		}
		return Verdict{Decision: d, Rule: fmt.Sprintf("%s[%d]", section, i), Reason: reason}
	}

	for i, r := range rules {
		d, ok := decisionFor(r, verb)
		if !ok {
			continue // this rule says nothing about this verb
		}
		if exactMatch(r.Match, target) {
			out = verdictFor(i, r, d)
			continue
		}
		if d != Allow && globMayCover(r.Match, target) && severity(d) > severity(out.Decision) {
			out = verdictFor(i, r, d)
		}
	}
	return out
}

func decisionFor(r Rule, verb effects.Verb) (Decision, bool) {
	if containsVerb(r.Deny, verb) {
		return Block, true
	}
	if containsVerb(r.Ask, verb) {
		return Ask, true
	}
	if containsVerb(r.Allow, verb) {
		return Allow, true
	}
	return "", false
}

func containsVerb(list []effects.Verb, v effects.Verb) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// exactMatch reports whether the rule's pattern matches the target as written.
func exactMatch(pattern, target string) bool {
	ok, err := doublestar.Match(pattern, target)
	return err == nil && ok
}

// globMayCover reports whether a rule could describe files that an unexpanded
// glob target would match.
//
// `rm *.log` inside a protected directory names no file yet, but every file it
// will name lives in that directory. Callers use this only to tighten a
// verdict, never to relax one.
func globMayCover(pattern, target string) bool {
	i := strings.IndexAny(target, "*?[")
	if i < 0 {
		return false // not a glob; exactMatch already had its say
	}
	dir := target[:i]
	if j := strings.LastIndexByte(dir, '/'); j > 0 {
		dir = dir[:j]
	}
	if ok, err := doublestar.Match(pattern, dir); err == nil && ok {
		return true
	}
	return strings.HasPrefix(pattern, dir+"/")
}

// evaluateGit applies the git section to notes left by the git extractor.
func evaluateGit(e effects.Effects, p *Policy) Verdict {
	out := Verdict{Decision: Allow, Rule: "default", Reason: "no rule matched"}
	forcePushDenied := false
	for _, d := range p.Git.Deny {
		if d == "force_push" {
			forcePushDenied = true
		}
	}
	if !forcePushDenied {
		return out
	}
	var forced bool
	var branch string
	for _, n := range e.Notes {
		if n == "git:push --force" {
			forced = true
		}
		if strings.HasPrefix(n, "git:push:") {
			branch = strings.TrimPrefix(n, "git:push:")
		}
	}
	if !forced {
		return out
	}
	for _, b := range p.Git.ProtectedBranches {
		if b == branch {
			return Verdict{
				Decision: Block,
				Rule:     "git.deny",
				Reason:   "force push to protected branch " + branch,
			}
		}
	}
	return out
}
