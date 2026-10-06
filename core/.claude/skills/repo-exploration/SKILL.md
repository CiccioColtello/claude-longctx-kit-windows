---
name: repo-exploration
description: Maps a repository or a part of it without filling the main context, by delegating exploration to subagents (repo-explorer, log-compressor, security-auditor). Use it when you must answer "where is X", "how does Y work", "what touches Z" across many files or on a codebase you do not know yet.
allowed-tools: Read, Grep, Glob, Agent, Task
---

# Repository exploration

## Principle

The main loop must contain **conclusions**, not files. Every exploratory read goes into a separate context that returns a few lines.

## When to delegate (and to whom)

| Situation | Subagent | Why |
|---|---|---|
| "Where is it / how does it work" across several files | `repo-explorer` | Many reads, synthetic output `path:line` |
| Output/build/log > 200 lines | `log-compressor` | Reduces to signal + discarded noise |
| Failed test/build | `test-diagnostician` | Isolates the root cause and the class |
| Before committing/sharing | `security-auditor` | Looks for secrets and dangerous commands |
| End of task / pre-compaction | `context-archivist` | Fixes the state in `.agent/` |

## Procedure

1. **Shape first, then content**: `Glob` for the structure, then `Grep` for the symbols, only afterwards a surgical `Read` (`offset`/`limit` on long files).
2. **One question per subagent**: "map the authentication flow" works; "explore the repo" does not.
3. **Demand the declaration of the limits**: every result must have COVERAGE/REST. A result without "what I did not read" is unreliable.
4. **Do not re-read what the subagent already summarized**: if you need a detail, ask it (same context) instead of re-reading the files.
5. **Always exclude**: `.git`, `node_modules`, `dist`, `build`, `target`, `vendor`, `coverage`, `.venv`, `__pycache__`, `.agent/archive`, `.agent/setup-backup`.

## Environment limits

- This project **is not a Git repository**: no `git log`/`git diff`. Subagents do not use `isolation: "worktree"`.
- Windows/PowerShell: do not assume shell `jq`, `sed`, `awk`, `grep`. The policy hooks block destructive commands and installations.
- Paths with spaces (`D:\my project`): always quote paths in invocations.

## Anti-patterns

- Reading 20 files in the main loop "they are small anyway": the cost is permanent in context.
- Delegating and then redoing the same search by hand: double cost, no gain.
- Accepting a subagent result without spot-checking one line when the decision is critical.
