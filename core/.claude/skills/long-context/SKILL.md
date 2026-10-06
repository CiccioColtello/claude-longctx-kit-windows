---
name: long-context
description: Strategies for long, token-expensive sessions: when to compact, what to keep, how to delegate, how to restart after a compaction using .agent/. Use it when the session gets long, when the context approaches the limit, or when you resume work after a compaction.
allowed-tools: Read, Grep, Glob, Write, Edit, Agent, Task
---

# Long context

Goal: **the work survives the session, not the transcript**. The useful state is in `.agent/`, not in the history.

## What is persistent (and what is not)

| Persistent | Ephemeral |
|---|---|
| `.agent/STATE.md` (goal, phase, next step) | The text of the messages |
| `.agent/DECISIONS.md` (decisions + rationale) | Command output |
| `.agent/FAILURES.md` (reproducible errors) | Discarded hypotheses |
| `.agent/CONTEXT.md` (structure, commands, constraints) | Files read to explore |
| `.agent/archive/*` (pre/post compaction snapshots) | Intermediate reasoning |

## Work cycle

1. **At the start of the session**: the SessionStart hook injects CONTEXT + STATE + latest decisions/failures. Read `STATE.md → Next action` and start from there. Do not re-explore what CONTEXT.md already describes.
2. **During**: every time you discover something durable (a command that works, a constraint, a key path), write it into `.agent/CONTEXT.md` right away. Memory that is not on disk does not exist.
3. **Before heavy operations**: if you are about to read a lot, delegate (`repo-explorer`, `log-compressor`) instead of inflating the main context.
4. **Before compaction**: the PreCompact hook saves a deterministic snapshot + a local digest (best-effort). Add explicit instructions with `/compact <instructions>` if there is something that must survive.
5. **After compaction**: the PostCompact hook writes the summary into `.agent/archive/` and updates `STATE.md`. If the summary lost a critical detail, recover it from the archive instead of rebuilding it from memory.

## Economy rules

- **A file read once is a permanent cost**: if you only need a symbol, use `Grep` with context, not a full `Read`.
- **Decisions are written when they are made**: rebuilding them later costs 10 times as much.
- **Deduplicate**: if the same error appears 3 times, do not re-read it — look for its class.
- **Stop early**: if an approach fails twice, change approach instead of insisting.

## What NEVER to put in `.agent/`

- Contents of `.env`/`.env.*`, keys, tokens, seeds, credentials → `[SENSITIVE_FILE] <name>`.
- Full transcripts, log dumps, long command output.
- Local model state passed off as truth: the Ollama digest is **best-effort and unverified**, not a security authority.

## Restart after a pause

1. `Read .agent/STATE.md` (or restart a session: the hook injects it).
2. Check `## Last compaction` in STATE.md and the latest file in `.agent/archive/INDEX.md`.
3. Verify the real state of the files cited in "Modified files" — **do not trust the summary**: read.
4. Restart from "Next action"; if it is empty or stale, ask the operator before proceeding.
