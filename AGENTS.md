# AGENTS.md

Guidance for AI coding agents (and humans) working on this repository.

## What this is

**vio** is a tiny, safety-first agent that runs and secures Linux servers over SSH.
It is a single Go binary. The LLM reasons with read-only tools; every change goes
through a typed plan → policy → approval → guarded apply → verify → audit pipeline.

- Full architecture and roadmap: [specs/plan.md](specs/plan.md) — read it before
  making structural changes.
- Decision log: [specs/decisions.md](specs/decisions.md) — append an entry for any
  architectural choice or new dependency.

Status: pre-alpha. Phases 0–4 are implemented; integration, lockout and injection-eval
suites are still missing (see `specs/plan.md` §11). Phase 5 (on-host agent) is out of
scope until those exist.

## Commands

```sh
go build ./...                 # build
go run ./cmd/vio               # run the CLI
go test ./...                  # unit tests
go test -race ./...            # unit tests with race detector (CI runs this)
go vet ./...                   # vet
staticcheck ./...              # lint (go install honnef.co/go/tools/cmd/staticcheck@latest)
govulncheck ./...              # vulnerability scan (go install golang.org/x/vuln/cmd/govulncheck@latest)
go test -tags integration ./test/integration/...   # needs Docker; Linux runner
```

Run `gofmt`, `go vet`, and the tests before declaring a task done.
The main developer works on Windows: keep the operator-side code portable
(`os.UserConfigDir`, `filepath`, no Unix-only syscalls outside `transport/local`).

## Layout

```
cmd/vio/            CLI entry and subcommand wiring
internal/agent      reasoning loop, budgets, context management
internal/llm        Provider interface + adapters
internal/transport  Executor interface; local + ssh
internal/tools      tool registry; observe/, change/, adapters/
internal/plan       Plan/Action model, hashing, diffs, preconditions
internal/policy     deterministic rules + restrict-only policy.yaml
internal/apply      guarded apply engine
internal/guard      lockout dead-man switch, validators, probes
internal/redact     secret masking
internal/audit      hash-chained JSONL log
internal/checks     deterministic security baseline (no LLM)
internal/sshconfig  ~/.ssh/config reader (hosts add <alias>, hosts import)
internal/facts      host facts (distro, init, package manager, firewall, SSH port)
internal/runbooks   embedded + operator markdown runbooks
specs/              plan.md, decisions.md
site/               landing page and docs.html (plain HTML/CSS, no build step)
assets/             logo
```

## Safety invariants — never break these

These are the product. A change that weakens any of them is a bug, even if tests pass.

1. **Observe tools never mutate.** If a tool can change host state, it is a
   `ChangeTool` in tier `change` or `dangerous`.
2. **Every `ChangeTool` implements `Plan`, `Apply`, and `Rollback`.** `Plan` must be
   side-effect free. A nil rollback is allowed only with the `irreversible` risk flag.
3. **Nothing mutates without an approved plan whose hash matches.** No shortcuts,
   no "just this once" code paths, no debug flags that skip policy.
4. **Policy is evaluated in code** before approval and again before execution.
   Never move a policy rule into a prompt.
5. **Access-affecting actions carry the `lockout` risk and run under a guard**
   with a fresh-connection probe.
6. **All tool output passes through `redact` before reaching the model or audit log.**
   Redaction fails closed.
7. **Host-derived data is never treated as instructions**, and change arguments that
   came from host data are marked tainted.
8. **Commands are argv, never string-concatenated shell** built from model input.
9. **SSH host keys are verified strictly.** No `InsecureIgnoreHostKey`, ever, outside tests.
10. **Secrets (API keys, sudo passwords) are never logged, audited, or sent to the model.**

## Code conventions

- Standard Go style; `gofmt`; package names short and lowercase.
- `context.Context` is the first parameter of anything that does I/O.
- Wrap errors with context: `fmt.Errorf("sshd.set: read config: %w", err)`.
- No global mutable state; pass dependencies explicitly.
- Interfaces are defined where they are consumed and kept small.
- Prefer the standard library. Adding a dependency requires an entry in
  `specs/decisions.md` explaining why the stdlib is not enough.
- Comments explain *why*, not *what*. Exported identifiers get doc comments.
- Tests are table-driven. Use `transport.Fake` and `llm.Fake`, not real hosts or models,
  in unit tests.
- Every change tool ships with: golden plan tests, a rollback test, and an
  integration test.

## Working style for agents

- Read `specs/plan.md` for the component you're touching before editing it.
- Keep changes small and focused; don't refactor unrelated code.
- If the spec and the code disagree, raise it — then update whichever is wrong.
- Never run vio's change tools against a real host from tests or scripts.
