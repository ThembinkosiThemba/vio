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
