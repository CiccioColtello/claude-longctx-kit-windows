---
name: context-maintenance
description: Keeps the project state files (.agent/STATE.md, DECISIONS.md, FAILURES.md, CONTEXT.md) up to date at the end of a task, before a compaction or when the work changes direction. Use it every time the work modifies files, closes a test or makes a durable decision.
allowed-tools: Read, Grep, Glob, Write, Edit
---

# Context maintenance

Keep `.agent/` compact, true and useful for the next session. The cost of a dishonest state file is a future session working on false premises.

## When to update

| Event | File | What to write |
|---|---|---|
| Task completed or interrupted | `STATE.md` | Goal, Phase, Modified files, Tests, Next action, Updated |
| Durable technical decision | `DECISIONS.md` | Date, decision, rationale, impacted files, discarded alternatives |
| Reproducible error | `FAILURES.md` | Timestamp, Component, Command, Error (first line, ~160 chars), Cause, Next verification |
| Project structure/commands change | `CONTEXT.md` | Only the changed sections |

## Procedure (5 steps)

1. **Gather the facts**: `git status`/`git diff` if the project is a repo; otherwise list the touched files. Do not use memory: verify.
2. **Update STATE.md** with surgical changes (Edit, not rewriting everything). Limit ~1500 characters.
3. **Decide whether an entry in DECISIONS.md is needed**: only if the decision binds future work. If it is a local detail, no.
4. **Record only real failures** observed. Never invent the cause: if you do not know it, write `to be verified`.
5. **Declare the REST**: what you could not verify.

## Non-negotiable rules

- Never secrets: no content of `.env`/`.env.*`, keys, tokens, credentials. If you run into one, cite `[SENSITIVE_FILE] <name>`.
- Never full logs or transcripts: only synthetic lines.
- Never `not verified` disguised as a fact: use literally `NOT VERIFIED`.
- Do not touch global files (`~/.claude/`) from this skill.

## Cheaper alternatives

If the main loop is already at half context, delegate to a `context-archivist` subagent with: touched files, tests run, next step. It costs a separate context and returns only the confirmation.
