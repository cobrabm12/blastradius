package effects

import (
	"strings"

	"github.com/cobrabm12/blastradius/internal/paths"
	"github.com/cobrabm12/blastradius/internal/shell"
)

func init() { Register("find", extractFind) }

// extractFind models find as acting on `<root>/<name pattern>`. Without -name,
// the whole subtree under the root is the radius.
func extractFind(inv shell.Invocation, ctx paths.Context) Effects {
	var e Effects
	root := "."
	pattern := ""
	deleting := false
	var execArgv []string

	args := inv.Argv[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-delete":
			deleting = true
		case "-name", "-iname", "-path", "-wholename":
			if i+1 < len(args) {
				pattern = args[i+1]
				i++
			}
		case "-exec", "-execdir", "-ok":
			for j := i + 1; j < len(args); j++ {
				if args[j] == ";" || args[j] == "+" {
					break
				}
				if args[j] != "{}" {
					execArgv = append(execArgv, args[j])
				}
			}
			i = len(args)
		default:
			if i == 0 && args[i] != "" && !strings.HasPrefix(args[i], "-") {
				root = args[i]
			}
		}
	}

	target := root
	if pattern != "" {
		target = strings.TrimSuffix(root, "/") + "/" + pattern
	}
	expanded := paths.Expand(target, ctx)

	if deleting {
		e.Deletes = append(e.Deletes, expanded...)
		e.Irreversible = true
	} else {
		e.Reads = append(e.Reads, expanded...)
	}

	// -exec runs another command once per match; analyze it against the matches.
	if len(execArgv) > 0 {
		nested := Extract(shell.Invocation{Argv: append(execArgv, target)}, ctx)
		e.Merge(nested)
	}
	return e
}
