package effects

import (
	"testing"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func ctx() paths.Context {
	return paths.Context{
		Cwd:  "/home/u/app",
		Home: "/home/u",
		Env:  map[string]string{"HOME": "/home/u"},
	}
}

func extract(t *testing.T, src string) Effects {
	t.Helper()
	invs, err := shell.Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	var total Effects
	for _, inv := range invs {
		total.Merge(Extract(inv, ctx()))
	}
	return total
}

func hasPath(list []paths.Path, want string) bool {
	for _, p := range list {
		if p.Abs == want {
			return true
		}
	}
	return false
}

func hasNote(e Effects, want string) bool {
	for _, n := range e.Notes {
		if n == want {
			return true
		}
	}
	return false
}

func hasRemote(e Effects, host string, verb Verb) bool {
	for _, r := range e.Remotes {
		if r.Host == host && r.Verb == verb {
			return true
		}
	}
	return false
}

// --- rm and the registry ---------------------------------------------------

func TestRmRecursiveSplitFlags(t *testing.T) {
	got := extract(t, `rm -r -f "$HOME/p"`)
	if !hasPath(got.Deletes, "/home/u/p") {
		t.Fatalf("Deletes = %+v, want /home/u/p", got.Deletes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true")
	}
}

func TestRmCombinedFlags(t *testing.T) {
	got := extract(t, `rm -rf /srv/data`)
	if !hasPath(got.Deletes, "/srv/data") {
		t.Errorf("Deletes = %+v, want /srv/data", got.Deletes)
	}
}

func TestRmDoubleDashEndsFlags(t *testing.T) {
	got := extract(t, `rm -f -- -weird-name`)
	if !hasPath(got.Deletes, "/home/u/app/-weird-name") {
		t.Errorf("Deletes = %+v, want /home/u/app/-weird-name", got.Deletes)
	}
}

func TestRmViaAbsolutePathIsStillRm(t *testing.T) {
	got := extract(t, `/bin/rm -rf /srv/data`)
	if !hasPath(got.Deletes, "/srv/data") {
		t.Errorf("Deletes = %+v, want /srv/data", got.Deletes)
	}
}

func TestUnregisteredCommandIsUnknown(t *testing.T) {
	got := extract(t, `frobnicate --wipe /srv`)
	if !got.Unknown {
		t.Error("Unknown = false, want true for an unregistered command")
	}
	if len(got.Deletes) != 0 {
		t.Errorf("Deletes = %+v, want none — an unknown command claims no effects", got.Deletes)
	}
}

// --- redirections and the rest of the filesystem ---------------------------

func TestTruncatingRedirectIsATruncate(t *testing.T) {
	got := extract(t, `: > production.db`)
	if !hasPath(got.Truncates, "/home/u/app/production.db") {
		t.Fatalf("Truncates = %+v, want /home/u/app/production.db", got.Truncates)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true: truncation discards content")
	}
}

func TestAppendRedirectIsAWriteNotATruncate(t *testing.T) {
	got := extract(t, `echo x >> log.txt`)
	if len(got.Truncates) != 0 {
		t.Errorf("Truncates = %+v, want none for >>", got.Truncates)
	}
	if !hasPath(got.Writes, "/home/u/app/log.txt") {
		t.Errorf("Writes = %+v, want /home/u/app/log.txt", got.Writes)
	}
}

func TestMvDeletesSourceAndWritesDestination(t *testing.T) {
	got := extract(t, `mv a.txt /srv/b.txt`)
	if !hasPath(got.Deletes, "/home/u/app/a.txt") {
		t.Errorf("Deletes = %+v, want the source /home/u/app/a.txt", got.Deletes)
	}
	if !hasPath(got.Writes, "/srv/b.txt") {
		t.Errorf("Writes = %+v, want /srv/b.txt", got.Writes)
	}
}

func TestDdIsIrreversible(t *testing.T) {
	got := extract(t, `dd if=/dev/zero of=/srv/disk.img`)
	if !hasPath(got.Writes, "/srv/disk.img") {
		t.Errorf("Writes = %+v, want /srv/disk.img", got.Writes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for dd")
	}
}

func TestTeeTruncatesEachOperand(t *testing.T) {
	got := extract(t, `cat x | tee a.log b.log`)
	if len(got.Truncates) != 2 {
		t.Errorf("Truncates = %+v, want two", got.Truncates)
	}
}

func TestTeeAppendIsAWrite(t *testing.T) {
	got := extract(t, `cat x | tee -a a.log`)
	if len(got.Truncates) != 0 || !hasPath(got.Writes, "/home/u/app/a.log") {
		t.Errorf("got truncates=%+v writes=%+v, want a single write", got.Truncates, got.Writes)
	}
}

func TestSedInPlaceIsAWrite(t *testing.T) {
	got := extract(t, `sed -i 's/a/b/' config.yaml`)
	if !hasPath(got.Writes, "/home/u/app/config.yaml") {
		t.Errorf("Writes = %+v, want /home/u/app/config.yaml", got.Writes)
	}
}

func TestSedWithoutInPlaceOnlyReads(t *testing.T) {
	got := extract(t, `sed 's/a/b/' config.yaml`)
	if len(got.Writes) != 0 {
		t.Errorf("Writes = %+v, want none without -i", got.Writes)
	}
	if !hasPath(got.Reads, "/home/u/app/config.yaml") {
		t.Errorf("Reads = %+v, want /home/u/app/config.yaml", got.Reads)
	}
}

func TestEchoNamesNoPaths(t *testing.T) {
	got := extract(t, `echo hello world`)
	if len(got.Reads)+len(got.Writes)+len(got.Deletes) != 0 {
		t.Errorf("got %+v, want no filesystem targets for echo", got)
	}
}

// --- find ------------------------------------------------------------------

func TestFindDeleteDeletesUnderTheSearchRoot(t *testing.T) {
	got := extract(t, `find . -name '*.db' -delete`)
	if !hasPath(got.Deletes, "/home/u/app/*.db") {
		t.Fatalf("Deletes = %+v, want the glob /home/u/app/*.db", got.Deletes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true")
	}
}

func TestFindWithoutDeleteOnlyReads(t *testing.T) {
	got := extract(t, `find /srv -name '*.log'`)
	if len(got.Deletes) != 0 {
		t.Errorf("Deletes = %+v, want none without -delete", got.Deletes)
	}
	if len(got.Reads) == 0 {
		t.Error("Reads is empty, want the search root")
	}
}

func TestFindExecRmIsAnalyzed(t *testing.T) {
	got := extract(t, `find /srv -name '*.tmp' -exec rm -f {} ;`)
	if len(got.Deletes) == 0 {
		t.Error("Deletes is empty, want the -exec rm target treated as a delete")
	}
}

// --- git -------------------------------------------------------------------

func TestGitCleanDeletesWorkingTree(t *testing.T) {
	got := extract(t, `git clean -xfd`)
	if !hasPath(got.Deletes, "/home/u/app") {
		t.Fatalf("Deletes = %+v, want the working tree /home/u/app", got.Deletes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true: git clean discards untracked files")
	}
}

func TestGitResetHardIsIrreversible(t *testing.T) {
	got := extract(t, `git reset --hard HEAD~3`)
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for reset --hard")
	}
}

func TestGitForcePushIsNotedAsIrreversible(t *testing.T) {
	got := extract(t, `git push --force origin main`)
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for a force push")
	}
	if !hasNote(got, "git:push --force") {
		t.Errorf("Notes = %q, want a git:push --force note", got.Notes)
	}
	if !hasNote(got, "git:push:main") {
		t.Errorf("Notes = %q, want the branch recorded", got.Notes)
	}
}

func TestGitStatusIsHarmless(t *testing.T) {
	got := extract(t, `git status`)
	if got.Irreversible || len(got.Deletes) != 0 {
		t.Errorf("got %+v, want no destructive effects for git status", got)
	}
}

// --- remotes ---------------------------------------------------------------

func TestSSHIsRemoteExec(t *testing.T) {
	got := extract(t, `ssh deploy@86.123.173.94 'systemctl restart app'`)
	if !hasRemote(got, "86.123.173.94", VerbExec) {
		t.Errorf("Remotes = %+v, want exec on 86.123.173.94", got.Remotes)
	}
}

func TestRsyncToRemoteIsRemoteWrite(t *testing.T) {
	got := extract(t, `rsync -av ./dist/ deploy@prod.ezweb.ro:/var/www/`)
	if !hasRemote(got, "prod.ezweb.ro", VerbWrite) {
		t.Errorf("Remotes = %+v, want write on prod.ezweb.ro", got.Remotes)
	}
}

func TestRsyncFromRemoteIsRemoteRead(t *testing.T) {
	got := extract(t, `rsync -av deploy@prod.ezweb.ro:/var/www/ ./dist/`)
	if !hasRemote(got, "prod.ezweb.ro", VerbRead) {
		t.Errorf("Remotes = %+v, want read on prod.ezweb.ro", got.Remotes)
	}
}

func TestPsqlDropIsIrreversibleRemoteWrite(t *testing.T) {
	got := extract(t, `psql -h db.ezweb.ro -c 'DROP TABLE orders'`)
	if !hasRemote(got, "db.ezweb.ro", VerbWrite) {
		t.Errorf("Remotes = %+v, want write on db.ezweb.ro", got.Remotes)
	}
	if !got.Irreversible {
		t.Error("Irreversible = false, want true for DROP")
	}
}

func TestPsqlSelectIsRemoteRead(t *testing.T) {
	got := extract(t, `psql -h db.ezweb.ro -c 'SELECT 1'`)
	if !hasRemote(got, "db.ezweb.ro", VerbRead) {
		t.Errorf("Remotes = %+v, want read on db.ezweb.ro", got.Remotes)
	}
}

func TestLocalDockerIsNotARemote(t *testing.T) {
	got := extract(t, `docker ps`)
	if len(got.Remotes) != 0 {
		t.Errorf("Remotes = %+v, want none without -H", got.Remotes)
	}
}

func TestDockerWithHostIsARemote(t *testing.T) {
	got := extract(t, `docker -H tcp://86.123.173.94:2375 ps`)
	if !hasRemote(got, "tcp://86.123.173.94:2375", VerbExec) {
		t.Errorf("Remotes = %+v, want the -H target", got.Remotes)
	}
}
