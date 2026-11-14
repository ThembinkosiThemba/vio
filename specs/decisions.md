# Decisions

Append-only log of architectural and technical decisions. Newest at the bottom.
Format: date, decision, why, alternatives considered.

---

## 2026-11-11 — Go, single static binary

**Decision:** vio is written in Go and ships as one static binary (`CGO_ENABLED=0`).
**Why:** First-class SSH library (`x/crypto/ssh`), trivial cross-compilation, the infra
ecosystem (Docker, Kubernetes, Terraform, Caddy) is Go, fast startup, easy concurrency.
**Alternatives:** Zig (fx's choice; smaller ecosystem for SSH/infra), Rust (slower to
iterate), TypeScript (needs a runtime on the operator machine).

## 2026-11-11 — Agentless over SSH

**Decision:** Targets need nothing installed. vio connects over SSH; the only host
state is `/var/lib/vio/{backups,guards}`.
**Why:** Zero-install adoption, smaller attack surface on targets.
**Alternatives:** On-host daemon (deferred to phase 5 as optional).

## 2026-11-11 — The model proposes, the code disposes

**Decision:** The reasoning loop only has observe tools. Mutations go through typed
plans, a deterministic policy engine, approval bound to the plan hash, and a guarded
apply engine.
**Why:** Live infrastructure has no undo; LLM output and host data cannot be trusted.

## 2026-11-11 — Stdlib-first, minimal dependencies

**Decision:** Stdlib `flag` for the CLI (no Cobra), `net/http` for OpenAI-compatible
providers (no SDK). Each new direct dependency is recorded here.
**Why:** Supply-chain risk for a tool that holds SSH access; binary size; startup time.

## 2026-11-11 — License: Apache-2.0

**Decision:** Apache License 2.0.
**Why:** Permissive, includes an explicit patent grant, standard for infra tooling.

## 2026-11-11 — Phase 0 dependencies

**Decision:** `golang.org/x/crypto` (ssh, knownhosts, agent), `go.yaml.in/yaml/v3`,
`golang.org/x/term`.
**Why:** The stdlib has no SSH client or YAML parser; `x/term` reads passwords without echo.

## 2026-11-11 — Chat-first CLI

**Decision:** Running `vio` with no arguments opens the agent chat. Subcommands remain
for scripting. The first run walks the operator through choosing a model provider.
**Why:** Everyday use should not require memorising flags.

## 2026-11-11 — Provider-neutral model layer

**Decision:** The agent talks to `internal/llm.Provider`, never to a vendor SDK. Two
adapters: OpenAI-compatible Chat Completions over `net/http` (Ollama, OpenAI,
OpenRouter, vLLM, LM Studio), and Anthropic via the official
`github.com/anthropics/anthropic-sdk-go/v2`.
**Why:** Operators must be able to use local models (Ollama) or any hosted API. The
Anthropic adapter uses the official SDK for correct streaming, prompt caching,
reasoning-block replay, and refusal fallbacks.
**Cost:** The SDK brings transitive modules (OpenTelemetry, gjson/sjson, jsonschema).
Revisit if binary size or audit surface becomes a problem.

## 2026-11-11 — Read-only agent tools use an argv allowlist

**Decision:** `run_command` accepts only allowlisted commands, checked per command for
write flags and subcommands (`internal/agent/allowlist.go`). No shell, no pipes. Files
holding password hashes or private keys are never read.
**Why:** Mutations belong to the plan/apply engine; the reasoning loop stays observe-only.

## 2026-11-12 — Tool names use snake_case

**Decision:** Tools are named `fs_write`, `sshd_set`, `svc_control`, ... instead of the
dotted `fs.write` in §5.7. The read-only escape hatches keep their names `run_command`
(spec `shell.ro`) and `read_file` (spec `fs.read`); `svc.start/stop/...` became one
`svc_control` tool with an `action` argument.
**Why:** Anthropic and OpenAI tool names must match `^[a-zA-Z0-9_-]+$`; dots are rejected.

## 2026-11-12 — Actions carry their exact steps

**Decision:** `ChangeTool.Plan` returns a `plan.Action` listing every step (`write` a
file, or `run` an argv) plus the rollback (files to restore, then argv to run). `Apply`
and `Rollback` are shared (`tools.Steps`) and only execute what the action lists; they
never re-derive commands from the tool arguments.
**Why:** Approval binds to the plan hash, so the hash must cover exactly what runs.
A tool whose `Apply` recomputed commands at apply time could run something the
operator never saw. Data-driven rollbacks also let the lockout guard write a
self-contained revert script for the host.

## 2026-11-12 — User policy is restrict-only YAML, not CEL

**Decision:** `~/.config/vio/policy.yaml` holds rules that match on tool, host, tag, tier
and risk (globs allowed) and can only `deny` or `confirm`. Built-in rules stay in Go.
**Why:** Covers the phase 3 exit criterion without adding `cel-go` and its transitive
modules. Restrict-only rules mean a policy file can never weaken a built-in protection.
Revisit Q1 if operators need conditions over facts or arguments.

## 2026-11-12 — Deterministic context compaction

**Decision:** Every tool output is kept in a session spool under a ref (`o1`, `o2`, ...).
When tool output in the conversation exceeds a byte budget, older large results are
replaced by their header plus a pointer to `output_read`. No summarization model call.
**Why:** No extra model cost or provider dependency, and nothing is lost: the model can
page back through any output.

## 2026-11-12 — Changes need root or passwordless sudo

**Decision:** vio elevates only with `sudo -n`. Change tools refuse to plan on hosts
where the login user is neither root nor allowed passwordless sudo. The sudo-password
prompt in §5.4 is not implemented.
**Why:** Holding and replaying a sudo password across the guard's fresh connections and
long-running steps adds secret-handling surface. Revisit with Q2 (keychain).

## 2026-11-12 — MCP server without an SDK

**Decision:** `vio mcp` speaks MCP's JSON-RPC over stdio with a small hand-written loop
(initialize, tools/list, tools/call, ping) and exposes only observe-tier tools.
**Why:** The surface is tiny; an SDK would be a new dependency for ~100 lines. Consuming
external MCP servers (phase 4) is not implemented.

## 2026-11-12 — Plan-file approvals are hash-bound, not signed

**Decision:** `vio apply --approve-only` records an approval (operator, time, hash) in the
plan file; a later `vio apply` honours it if the hash still matches. Approvals are not
cryptographically signed yet (Q4 stays open).
**Why:** Enables the second-operator workflow now. Anyone who can write the file and run
vio could also approve interactively, so this adds no new capability; docs say so.

## 2026-11-14 — Zero-detail host attach: `local` hosts and a stdlib ssh-config reader

**Decision:** Inventory hosts gain `local: true` for the machine vio runs on (served by
`transport.Local`, no SSH, no host key). `local` excludes `addr`, `port`, `user` and
`identity`, so `Validate` stays strict for both kinds rather than allowing half-empty
SSH hosts. `vio hosts add <alias>` and `vio hosts import` read `~/.ssh/config` through a
new `internal/sshconfig` package: Host/HostName/User/Port/IdentityFile/Include,
first-match-wins, `~` and `%h`/`%d` expansion, quotes. Constructs vio cannot honour
(`Match`, `ProxyJump`, `ProxyCommand`, `HostKeyAlias`, ...) become warnings on the host's
notes. The model's `add_host` can never create a local host. Keys already in
`~/.ssh/known_hosts` are reused by `hosts trust` without a prompt (they were already
honoured at dial time); unknown keys still fail closed.
**Why:** The details vio asked for are already on the operator's machine; retyping them
causes typos and drift from what `ssh` does. The subset of ssh_config needed is ~300
lines, so a dependency (e.g. `kevinburke/ssh_config`) is not worth its surface.
**Alternatives:** Shelling out to `ssh -G <alias>` (needs OpenSSH on the operator
machine and runs `Match exec`, i.e. arbitrary commands from config); a third-party
parser; relaxing `Validate` to allow missing `addr`/`user`.
