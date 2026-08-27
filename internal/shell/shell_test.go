package shell

import "testing"

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseSimpleCommand(t *testing.T) {
	invs, err := Parse(`rm -r -f /tmp/x`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(invs) != 1 {
		t.Fatalf("got %d invocations, want 1", len(invs))
	}
	want := []string{"rm", "-r", "-f", "/tmp/x"}
	if got := invs[0].Argv; !equal(got, want) {
		t.Errorf("Argv = %q, want %q", got, want)
	}
}

func TestParseQuotingAndVariables(t *testing.T) {
	invs, err := Parse(`rm -rf "$HOME/p" '/lit eral'`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{"rm", "-rf", "${HOME}/p", "/lit eral"}
	if got := invs[0].Argv; !equal(got, want) {
		t.Errorf("Argv = %q, want %q", got, want)
	}
}

func TestParseCommandSubstitutionIsUnresolvable(t *testing.T) {
	invs, err := Parse(`rm -rf $(cat target.txt)`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !invs[0].Unknown {
		t.Error("Unknown = false, want true for command substitution")
	}
	if invs[0].Argv[2] != Unresolvable {
		t.Errorf("Argv[2] = %q, want the Unresolvable sentinel", invs[0].Argv[2])
	}
}

func TestParseTruncatingRedirect(t *testing.T) {
	invs, err := Parse(`: > production.db`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(invs) != 1 {
		t.Fatalf("got %d invocations, want 1", len(invs))
	}
	if len(invs[0].Redirects) != 1 {
		t.Fatalf("got %d redirects, want 1", len(invs[0].Redirects))
	}
	r := invs[0].Redirects[0]
	if r.Op != RedirWrite || r.Target != "production.db" {
		t.Errorf("redirect = %+v, want {RedirWrite production.db}", r)
	}
}

func TestParsePipelineAndChain(t *testing.T) {
	invs, err := Parse(`cat a | tee b && rm -rf c`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(invs) != 3 {
		t.Fatalf("got %d invocations, want 3", len(invs))
	}
	if invs[0].Argv[0] != "cat" || invs[1].Argv[0] != "tee" || invs[2].Argv[0] != "rm" {
		t.Errorf("commands = %q/%q/%q, want cat/tee/rm",
			invs[0].Argv[0], invs[1].Argv[0], invs[2].Argv[0])
	}
}

func TestParseAppendRedirect(t *testing.T) {
	invs, err := Parse(`echo x >> log.txt`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if invs[0].Redirects[0].Op != RedirAppend {
		t.Errorf("op = %v, want RedirAppend", invs[0].Redirects[0].Op)
	}
}

func TestParseDescendsIntoBashDashC(t *testing.T) {
	invs, err := Parse(`bash -c 'rm -rf ~/data'`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var found bool
	for _, inv := range invs {
		if inv.Argv[0] == "rm" && inv.Argv[len(inv.Argv)-1] == "~/data" {
			found = true
		}
	}
	if !found {
		t.Errorf("no rm invocation recovered from bash -c; got %+v", invs)
	}
}

func TestParseStripsSudoAndEnvPrefixes(t *testing.T) {
	for _, src := range []string{`sudo rm -rf /srv/x`, `env FOO=1 rm -rf /srv/x`} {
		invs, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if invs[0].Argv[0] != "rm" {
			t.Errorf("Parse(%q) argv[0] = %q, want rm", src, invs[0].Argv[0])
		}
	}
}

func TestParseXargsYieldsTrailingCommandAsUnknown(t *testing.T) {
	invs, err := Parse(`xargs rm < filelist`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var rm *Invocation
	for i := range invs {
		if invs[i].Argv[0] == "rm" {
			rm = &invs[i]
		}
	}
	if rm == nil {
		t.Fatal("no rm invocation recovered from xargs")
	}
	if !rm.Unknown {
		t.Error("Unknown = false, want true: xargs supplies argv from stdin")
	}
}

func TestParseAbsoluteBinaryPathResolvesLikeBareName(t *testing.T) {
	invs, err := Parse(`/bin/rm -rf /srv/x`)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if invs[0].Argv[0] != "/bin/rm" {
		t.Errorf("Argv[0] = %q, want the path preserved for reporting", invs[0].Argv[0])
	}
}

func TestParseFuzzDoesNotPanic(t *testing.T) {
	// Malformed input reaching a guardrail is the expected case.
	for _, src := range []string{"", "   ", "rm -rf 'unterminated", "$(", "|||", "for i in; do", "\x00"} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("Parse(%q) panicked: %v", src, r)
				}
			}()
			_, _ = Parse(src)
		}()
	}
}
