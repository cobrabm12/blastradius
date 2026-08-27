package policy

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
)

func mustLoad(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return p
}

func abs(p string) paths.Path {
	return paths.Path{Raw: p, Abs: p, Resolved: true}
}

func TestBlocksDeniedDelete(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/prod/**"
    deny: [delete]
    reason: "Production data."
`)
	v := Evaluate(effects.Effects{Deletes: []paths.Path{abs("/srv/prod/db.sqlite")}}, p)
	if v.Decision != Block {
		t.Errorf("Decision = %q, want block", v.Decision)
	}
	if v.Reason != "Production data." {
		t.Errorf("Reason = %q, want the rule's reason", v.Reason)
	}
	if v.Rule != "paths[0]" {
		t.Errorf("Rule = %q, want paths[0]", v.Rule)
	}
}

func TestLastMatchingRuleWins(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/**"
    deny: [delete]
  - match: "/srv/**/node_modules/**"
    allow: [delete]
`)
	v := Evaluate(effects.Effects{Deletes: []paths.Path{abs("/srv/app/node_modules/x")}}, p)
	if v.Decision != Allow {
		t.Errorf("Decision = %q, want allow: the later exception governs", v.Decision)
	}
}

func TestRuleSilentOnAVerbDoesNotDecide(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/**"
    deny: [delete]
`)
	v := Evaluate(effects.Effects{Reads: []paths.Path{abs("/srv/app/x")}}, p)
	if v.Decision != Allow {
		t.Errorf("Decision = %q, want allow: the rule says nothing about read", v.Decision)
	}
}

func TestMostSevereDecisionAcrossRadiusWins(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/prod/**"
    deny: [delete]
`)
	e := effects.Effects{Deletes: []paths.Path{abs("/tmp/scratch"), abs("/srv/prod/db")}}
	if v := Evaluate(e, p); v.Decision != Block {
		t.Errorf("Decision = %q, want block: one denied path condemns the command", v.Decision)
	}
}

func TestUnmatchedPathIsAllowed(t *testing.T) {
	p := mustLoad(t, "version: 1\n")
	v := Evaluate(effects.Effects{Deletes: []paths.Path{abs("/tmp/x")}}, p)
	if v.Decision != Allow {
		t.Errorf("Decision = %q, want allow when no rule matches", v.Decision)
	}
}

func TestUnknownRoutesToOnError(t *testing.T) {
	p := mustLoad(t, "version: 1\non_error: block\n")
	v := Evaluate(effects.Effects{Unknown: true}, p)
	if v.Decision != Block {
		t.Errorf("Decision = %q, want block from on_error", v.Decision)
	}
	if v.Rule != "on_error" {
		t.Errorf("Rule = %q, want on_error", v.Rule)
	}
}

func TestOnErrorAllowIsHonouredWhenChosen(t *testing.T) {
	p := mustLoad(t, "version: 1\non_error: allow\n")
	if v := Evaluate(effects.Effects{Unknown: true}, p); v.Decision != Allow {
		t.Errorf("Decision = %q, want allow when the operator chose it explicitly", v.Decision)
	}
}

func TestUnresolvedPathIsUnknown(t *testing.T) {
	p := mustLoad(t, "version: 1\non_error: ask\n")
	e := effects.Effects{Deletes: []paths.Path{{Raw: "${NOPE}", Resolved: false}}}
	if v := Evaluate(e, p); v.Decision != Ask {
		t.Errorf("Decision = %q, want ask: an unresolved path is not a safe path", v.Decision)
	}
}

func TestHostRulesApply(t *testing.T) {
	p := mustLoad(t, `
version: 1
hosts:
  - match: "*.ezweb.ro"
    ask: [write, exec]
`)
	e := effects.Effects{Remotes: []effects.Remote{{Host: "prod.ezweb.ro", Verb: effects.VerbExec}}}
	if v := Evaluate(e, p); v.Decision != Ask {
		t.Errorf("Decision = %q, want ask", v.Decision)
	}
}

func TestForcePushToProtectedBranchIsBlocked(t *testing.T) {
	p := mustLoad(t, `
version: 1
git:
  protected_branches: [main]
  deny: [force_push]
`)
	e := effects.Effects{Notes: []string{"git:push --force", "git:push:main"}}
	v := Evaluate(e, p)
	if v.Decision != Block {
		t.Errorf("Decision = %q, want block", v.Decision)
	}
	if v.Rule != "git.deny" {
		t.Errorf("Rule = %q, want git.deny", v.Rule)
	}
}

func TestForcePushToUnprotectedBranchIsAllowed(t *testing.T) {
	p := mustLoad(t, `
version: 1
git:
  protected_branches: [main]
  deny: [force_push]
`)
	e := effects.Effects{Notes: []string{"git:push --force", "git:push:feature-x"}}
	if v := Evaluate(e, p); v.Decision != Allow {
		t.Errorf("Decision = %q, want allow on an unprotected branch", v.Decision)
	}
}

func TestGlobTargetStillMatchesADirectoryRule(t *testing.T) {
	// `rm *.db` in a protected directory must not slip through merely because
	// the exact filenames are unknown until the shell expands them.
	p := mustLoad(t, `
version: 1
paths:
  - match: "/srv/prod/**"
    deny: [delete]
`)
	e := effects.Effects{Deletes: []paths.Path{{Raw: "*.db", Abs: "/srv/prod/*.db", Resolved: true, IsGlob: true}}}
	if v := Evaluate(e, p); v.Decision != Block {
		t.Errorf("Decision = %q, want block for a glob inside a protected directory", v.Decision)
	}
}

func TestVerdictAlwaysCarriesProvenance(t *testing.T) {
	p := mustLoad(t, "version: 1\n")
	v := Evaluate(effects.Effects{Reads: []paths.Path{abs("/tmp/x")}}, p)
	if v.Rule == "" {
		t.Error("Rule is empty: a verdict without provenance is a bug")
	}
}

func TestRadiusIsCarriedIntoTheVerdict(t *testing.T) {
	p := mustLoad(t, "version: 1\n")
	e := effects.Effects{Deletes: []paths.Path{abs("/tmp/x")}}
	v := Evaluate(e, p)
	if len(v.Radius.Deletes) != 1 {
		t.Errorf("Radius.Deletes = %+v, want the analyzed radius", v.Radius.Deletes)
	}
}

// TestPermissiveRuleCannotAbsorbAGlob is a regression test for a real hole.
//
// The conservative widening that lets `rm *.db` match a rule protecting its
// directory once applied to permissive rules too. Because the last matching
// rule wins, a trailing `allow` exception — node_modules, say — then matched
// every glob in the project and cancelled every protection above it.
func TestPermissiveRuleCannotAbsorbAGlob(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/app/**/*.db"
    deny: [delete, truncate]
    reason: "Databases are add-only."
  - match: "/app/**/node_modules/**"
    allow: [delete, truncate, write]
`)
	e := effects.Effects{Deletes: []paths.Path{
		{Raw: "*.db", Abs: "/app/*.db", Resolved: true, IsGlob: true},
	}}
	v := Evaluate(e, p)
	if v.Decision != Block {
		t.Errorf("Decision = %q (rule %s), want block: an unrelated allow rule must not absorb a glob",
			v.Decision, v.Rule)
	}
}

// TestExactAllowExceptionStillWins confirms the fix did not break the feature
// the exception exists for: a real path inside node_modules is still deletable.
func TestExactAllowExceptionStillWins(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/app/**"
    deny: [delete]
  - match: "/app/**/node_modules/**"
    allow: [delete]
`)
	e := effects.Effects{Deletes: []paths.Path{abs("/app/node_modules/left-pad")}}
	if v := Evaluate(e, p); v.Decision != Allow {
		t.Errorf("Decision = %q, want allow: the exception must still work for real paths", v.Decision)
	}
}

// TestGlobInsideAnAllowedDirectoryIsStillAllowed keeps the fix from turning
// every glob into a block: a glob whose directory is exactly covered by an
// allow rule matches it exactly, not by widening.
func TestGlobInsideAnAllowedDirectoryIsStillAllowed(t *testing.T) {
	p := mustLoad(t, `
version: 1
paths:
  - match: "/app/**"
    deny: [delete]
  - match: "/app/dist/*"
    allow: [delete]
`)
	e := effects.Effects{Deletes: []paths.Path{
		{Raw: "dist/*", Abs: "/app/dist/*", Resolved: true, IsGlob: true},
	}}
	if v := Evaluate(e, p); v.Decision != Allow {
		t.Errorf("Decision = %q, want allow: the glob matches the allow rule exactly", v.Decision)
	}
}
