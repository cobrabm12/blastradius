package paths

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/shell"
)

func ctx() Context {
	return Context{
		Cwd:  "/home/u/app",
		Home: "/home/u",
		Env:  map[string]string{"HOME": "/home/u", "TARGET": "/srv/data"},
	}
}

func TestExpandTilde(t *testing.T) {
	got := Expand("~/data", ctx())
	if len(got) != 1 || got[0].Abs != "/home/u/data" || !got[0].Resolved {
		t.Errorf("got %+v, want one resolved /home/u/data", got)
	}
}

func TestExpandBareTilde(t *testing.T) {
	got := Expand("~", ctx())
	if got[0].Abs != "/home/u" {
		t.Errorf("Abs = %q, want /home/u", got[0].Abs)
	}
}

func TestExpandVariable(t *testing.T) {
	got := Expand("${TARGET}/x", ctx())
	if len(got) != 1 || got[0].Abs != "/srv/data/x" {
		t.Errorf("got %+v, want /srv/data/x", got)
	}
}

func TestExpandUnsetVariableIsUnresolved(t *testing.T) {
	got := Expand("${NOPE}/x", ctx())
	if len(got) != 1 || got[0].Resolved {
		t.Errorf("got %+v, want a single unresolved path", got)
	}
}

func TestExpandRelativeAgainstCwd(t *testing.T) {
	got := Expand("build", ctx())
	if got[0].Abs != "/home/u/app/build" {
		t.Errorf("Abs = %q, want /home/u/app/build", got[0].Abs)
	}
}

func TestExpandBraces(t *testing.T) {
	got := Expand("/srv/{a,b}/x", ctx())
	if len(got) != 2 || got[0].Abs != "/srv/a/x" || got[1].Abs != "/srv/b/x" {
		t.Errorf("got %+v, want /srv/a/x and /srv/b/x", got)
	}
}

func TestExpandGlobIsMarkedNotExpanded(t *testing.T) {
	got := Expand("*.db", ctx())
	if len(got) != 1 || !got[0].IsGlob || got[0].Abs != "/home/u/app/*.db" {
		t.Errorf("got %+v, want a single glob /home/u/app/*.db", got)
	}
}

func TestExpandUnresolvableSentinel(t *testing.T) {
	got := Expand(shell.Unresolvable, ctx())
	if len(got) != 1 || got[0].Resolved {
		t.Errorf("got %+v, want a single unresolved path", got)
	}
}

func TestExpandCleansTraversal(t *testing.T) {
	got := Expand("/srv/app/../../etc/passwd", ctx())
	if got[0].Abs != "/etc/passwd" {
		t.Errorf("Abs = %q, want /etc/passwd — traversal must not hide the real target", got[0].Abs)
	}
}

func TestExpandRelativeTraversalEscapesCwd(t *testing.T) {
	got := Expand("../../prod", ctx())
	if got[0].Abs != "/home/prod" {
		t.Errorf("Abs = %q, want /home/prod", got[0].Abs)
	}
}

// TestResolutionIsHostIndependent pins the decision to use POSIX semantics
// rather than the host's. The analyzer must return the same verdict for the
// same command regardless of which operating system it runs on.
func TestResolutionIsHostIndependent(t *testing.T) {
	got := Expand("/srv/data", ctx())
	if got[0].Abs != "/srv/data" {
		t.Errorf("Abs = %q, want /srv/data with forward slashes on every platform", got[0].Abs)
	}
	if joined := Expand("sub/dir", ctx()); joined[0].Abs != "/home/u/app/sub/dir" {
		t.Errorf("Abs = %q, want forward-slash joining on every platform", joined[0].Abs)
	}
}
