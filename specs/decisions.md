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
