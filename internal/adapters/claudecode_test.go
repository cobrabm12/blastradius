package adapters

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cobrabm12/blastradius/internal/policy"
)

func TestDecodeBashToolCall(t *testing.T) {
	in := `{"session_id":"s1","cwd":"/home/u/app","hook_event_name":"PreToolUse",
	        "tool_name":"Bash","tool_input":{"command":"rm -rf /srv"}}`
	req, err := DecodeClaudeCode(strings.NewReader(in))
	if err != nil {
		t.Fatalf("DecodeClaudeCode: %v", err)
	}
	cmd, ok := req.CommandFor()
	if !ok || cmd != "rm -rf /srv" {
		t.Errorf("CommandFor() = %q, %v; want the bash command", cmd, ok)
	}
	if req.Cwd != "/home/u/app" {
		t.Errorf("Cwd = %q, want /home/u/app", req.Cwd)
	}
}

func TestWriteToolBecomesAFilesystemWrite(t *testing.T) {
	in := `{"tool_name":"Write","cwd":"/home/u/app","tool_input":{"file_path":"/home/u/prod/.env"}}`
	req, err := DecodeClaudeCode(strings.NewReader(in))
	if err != nil {
		t.Fatalf("DecodeClaudeCode: %v", err)
	}
	cmd, ok := req.CommandFor()
	if !ok {
		t.Fatal("CommandFor() reported no command for a Write tool call")
	}
	if !strings.Contains(cmd, "/home/u/prod/.env") {
		t.Errorf("CommandFor() = %q, want the target path", cmd)
	}
}

func TestUnhandledToolIsSkipped(t *testing.T) {
	in := `{"tool_name":"WebFetch","tool_input":{}}`
	req, _ := DecodeClaudeCode(strings.NewReader(in))
	if _, ok := req.CommandFor(); ok {
		t.Error("CommandFor() claimed a command for a tool that touches no files")
	}
}

func TestPathWithQuoteIsQuotedSafely(t *testing.T) {
	in := `{"tool_name":"Write","tool_input":{"file_path":"/home/u/it's.txt"}}`
	req, _ := DecodeClaudeCode(strings.NewReader(in))
	cmd, ok := req.CommandFor()
	if !ok {
		t.Fatal("CommandFor() reported no command")
	}
	if !strings.Contains(cmd, `'\''`) {
		t.Errorf("CommandFor() = %q, want the embedded quote escaped", cmd)
	}
}

func TestEncodeMapsDecisionsToClaudeVocabulary(t *testing.T) {
	cases := map[policy.Decision]string{
		policy.Block: "deny",
		policy.Ask:   "ask",
		policy.Allow: "allow",
	}
	for decision, want := range cases {
		var sb strings.Builder
		err := EncodeClaudeCode(&sb, policy.Verdict{Decision: decision, Reason: "r", Rule: "paths[0]"})
		if err != nil {
			t.Fatalf("EncodeClaudeCode: %v", err)
		}
		var resp ClaudeCodeResponse
		if err := json.Unmarshal([]byte(sb.String()), &resp); err != nil {
			t.Fatalf("unmarshal response: %v", err)
		}
		if got := resp.HookSpecificOutput.PermissionDecision; got != want {
			t.Errorf("decision %q encoded as %q, want %q", decision, got, want)
		}
		if resp.HookSpecificOutput.HookEventName != "PreToolUse" {
			t.Errorf("hookEventName = %q, want PreToolUse", resp.HookSpecificOutput.HookEventName)
		}
	}
}

func TestReasonNamesTheDecidingRule(t *testing.T) {
	got := Reason(policy.Verdict{Reason: "Production data.", Rule: "paths[2]"})
	if !strings.Contains(got, "paths[2]") {
		t.Errorf("Reason = %q, want the rule named so the user can find it", got)
	}
}
