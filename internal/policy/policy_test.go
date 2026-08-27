package policy

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/effects"
	"github.com/cobrabm12/blastradius/internal/paths"
)

const sample = `
version: 1
on_error: ask
paths:
  - match: "/home/u/prod/**"
    deny: [write, delete, truncate]
    reason: "Production source."
  - match: "**/node_modules/**"
    allow: [delete, truncate]
hosts:
  - match: "86.123.173.94"
    deny: [write, exec]
git:
  protected_branches: [main]
  deny: [force_push]
`

func TestLoadParsesRules(t *testing.T) {
	p, err := Load([]byte(sample))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.OnError != Ask {
		t.Errorf("OnError = %q, want ask", p.OnError)
	}
	if len(p.Paths) != 2 || p.Paths[0].Match != "/home/u/prod/**" {
		t.Fatalf("Paths = %+v, want two rules starting with /home/u/prod/**", p.Paths)
	}
	if len(p.Paths[0].Deny) != 3 || p.Paths[0].Deny[0] != effects.VerbWrite {
		t.Errorf("Deny = %+v, want [write delete truncate]", p.Paths[0].Deny)
	}
	if len(p.Hosts) != 1 || p.Hosts[0].Match != "86.123.173.94" {
		t.Errorf("Hosts = %+v, want one rule for 86.123.173.94", p.Hosts)
	}
}

func TestLoadDefaultsOnErrorToAsk(t *testing.T) {
	p, err := Load([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.OnError != Ask {
		t.Errorf("OnError = %q, want ask by default", p.OnError)
	}
}

func TestLoadRejectsUnknownVerb(t *testing.T) {
	_, err := Load([]byte("version: 1\npaths:\n  - match: \"x\"\n    deny: [detonate]\n"))
	if err == nil {
		t.Fatal("Load accepted the verb \"detonate\", want an error")
	}
}

func TestLoadRejectsExecInPathSection(t *testing.T) {
	_, err := Load([]byte("version: 1\npaths:\n  - match: \"x\"\n    deny: [exec]\n"))
	if err == nil {
		t.Fatal("Load accepted exec as a path verb, want an error")
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	if _, err := Load([]byte("version: 99\n")); err == nil {
		t.Fatal("Load accepted version 99, want an error")
	}
}

func TestLoadRejectsRuleWithoutVerbs(t *testing.T) {
	if _, err := Load([]byte("version: 1\npaths:\n  - match: \"x\"\n")); err == nil {
		t.Fatal("Load accepted a rule naming no verbs, want an error")
	}
}

func TestMergePutsUserRulesLast(t *testing.T) {
	repo, err := Load([]byte("version: 1\npaths:\n  - match: \"**\"\n    allow: [delete]\n"))
	if err != nil {
		t.Fatalf("Load repo: %v", err)
	}
	user, err := Load([]byte("version: 1\npaths:\n  - match: \"/home/u/prod/**\"\n    deny: [delete]\n"))
	if err != nil {
		t.Fatalf("Load user: %v", err)
	}
	m := Merge(repo, user)
	if len(m.Paths) != 2 {
		t.Fatalf("Paths = %+v, want two", m.Paths)
	}
	if m.Paths[1].Match != "/home/u/prod/**" {
		t.Errorf("last rule = %q, want the user rule to come last", m.Paths[1].Match)
	}
}

func TestMergeMeansRepoCannotRelaxMachinePolicy(t *testing.T) {
	user, _ := Load([]byte("version: 1\npaths:\n  - match: \"/home/u/prod/**\"\n    deny: [delete]\n"))
	repo, _ := Load([]byte("version: 1\npaths:\n  - match: \"**\"\n    allow: [delete]\n"))
	m := Merge(repo, user)

	e := effects.Effects{Deletes: []paths.Path{abs("/home/u/prod/db")}}
	if v := Evaluate(e, m); v.Decision != Block {
		t.Errorf("Decision = %q, want block: a repository must not be able to relax machine policy", v.Decision)
	}
}
