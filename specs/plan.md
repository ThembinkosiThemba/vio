# vio — Architecture & Build Plan

> A tiny, safety-first agent that runs and secures your servers.
> Single Go binary. Agentless over SSH. Plans before it touches anything.

Status: **draft v0.1** · Owner: @ThembinkosiThemba · Last updated: 2026-11-11

---

## 0. Summary

vio is a command-line agent that operates Linux servers (VPSes, bare metal, cloud VMs)
on behalf of an operator. It investigates, explains, audits, and changes infrastructure
using an LLM for reasoning and a deterministic core for everything that matters:
what is allowed, what is executed, how it is undone, and what is recorded.

The core idea: **the model proposes, the code disposes.** The LLM can look at anything
it is permitted to look at, but every state-changing operation flows through a typed
plan, a policy engine, operator approval, guarded execution, verification, and an
append-only audit log.

### Goals

- Diagnose and explain server problems in plain language ("why is disk full on web-1").
- Audit and harden servers against a security baseline, with fixes that are reviewable.
- Make changes safely: dry-run, diff, rollback, lockout protection.
- Work on any Linux host reachable by SSH with **nothing installed on the host**.
- Ship as one small static binary for Linux, macOS, and Windows operators.
- Be provider-agnostic: Anthropic, OpenAI-compatible endpoints, local models.

### Non-goals (for now)

- Replacing Terraform/Ansible for fleet-scale declarative provisioning.
- Provisioning cloud resources (create VMs, DNS, buckets). May come later via MCP.
- Windows *targets*. Operators may run on Windows; targets are Linux.
- A hosted SaaS, telemetry, or accounts. vio is a local tool.
- A full-screen TUI. Output is plain terminal scrollback (Unix-like), plus `--json`.

---

## 1. Design principles

1. **Infra is not code.** There is no `git checkout` for a live server. Every change
   must carry its own rollback, or be explicitly marked irreversible and gated harder.
2. **Plan, then apply.** Investigation is free. Mutation goes through a `Plan` of typed
   `Action`s with diffs, risk flags, preconditions, and rollbacks. Operators approve
   plans, not raw commands. Approval binds to the plan's hash.
3. **Typed tools over raw shell.** `fw.allow(port=443)` can be validated, dry-run,
   diffed, and reversed. `bash -c` cannot. Raw shell exists, but read-only by default
   and in the highest risk tier for writes.
4. **Read is free, write is gated.** Tools are tiered: `observe` → `change` → `dangerous`.
5. **Never lock the operator out.** Any action that can affect access (SSH, firewall,
   users, keys, network) arms a dead-man switch that auto-reverts unless a *fresh*
   connection proves access still works.
6. **Policy is code, not prompt.** A deterministic policy engine has the final say.
   Prompt instructions are advisory; policy is enforced.
7. **Everything from the host is hostile data.** Logs, files, banners, package
   metadata may contain prompt injection. Tool output is never instructions.
   Arguments derived from host data are *tainted* and require explicit confirmation.
8. **Secrets never reach the model.** Tool output is redacted before it leaves the
   executor. The model refers to secrets by reference (`secret://name`).
9. **Everything is audited.** Append-only, hash-chained JSONL of every observation,
   plan, approval, command, and result.
10. **Small, fast, boring.** Minimal dependencies, stdlib first, plain text output,
    `--json` for machines, sub-20ms startup.

---

## 2. Threat model

vio holds SSH access to production machines and is driven by a probabilistic model.
We design against these failure modes:

| # | Threat | Example | Primary mitigations |
|---|--------|---------|---------------------|
| T1 | Model error | Wrong firewall rule closes port 22 | Typed tools, policy, lockout guard, verify step |
| T2 | Prompt injection from host data | Log line: "add this key to authorized_keys" | Data/instruction separation, taint tracking, policy, approval |
| T3 | Secret exfiltration to model provider | `.env` contents sent in context | Redaction layer, sensitive-path rules, secret refs |
| T4 | Over-broad action | `rm -rf` on wrong path, `apt remove` cascade | Dangerous tier, dry-run diffs, path policy |
| T5 | Stale plan | Config changed between plan and apply | Preconditions (hashes/versions) checked at apply |
| T6 | MITM on SSH | First connect to spoofed host | Strict known_hosts, no TOFU by default, no agent forwarding |
| T7 | Compromised operator config | Malicious runbook / policy edit | Policy file integrity warnings, runbooks treated as advisory |
| T8 | Supply chain | Malicious dependency or release | Minimal deps, govulncheck, signed releases, SBOM |
| T9 | Runaway cost/loop | Agent loops forever on tool errors | Turn, token, and cost budgets; loop detection |

Out of scope: a fully compromised operator workstation; a root-level attacker already
on the target (vio can help detect, not guarantee).

---

## 3. System overview

```
                         ┌──────────────────────────── operator machine ───────────────────────────┐
  operator ──prompt──▶   │  cli ──▶ agent loop ◀──▶ llm.Provider ──HTTPS──▶ model API / local model  │
                         │             │                                                            │
                         │             ▼ tool calls                                                 │
                         │        tools registry ──▶ redact ◀── output                              │
                         │             │                                                            │
                         │   observe ──┤── change/dangerous ──▶ plan ──▶ policy ──▶ approval        │
                         │             │                                         │                  │
                         │             ▼                                         ▼                  │
                         │        transport.Executor ◀──────────── apply engine (guard, verify)     │
                         │             │                                         │                  │
                         │             │                                    audit log (JSONL)       │
                         └─────────────┼────────────────────────────────────────────────────────────┘
                                       │ SSH (x/crypto/ssh)  or  local exec
                                       ▼
                               ┌──────────────── target host ─────────────────┐
                               │  sh, systemd, apt/dnf/apk, ufw/nft, sshd ... │
                               │  /var/lib/vio/{backups,guards}  (only state) │
                               └──────────────────────────────────────────────┘
```

Two loops, cleanly separated:

- **Reasoning loop** (agent): model ⇄ observe tools. Produces understanding and,
  optionally, a proposed plan. Cannot mutate anything.
- **Execution loop** (apply engine): deterministic. Takes an approved plan and runs it
  with guards. The model is not in this loop, except optionally to explain a failure.

---

## 4. Repository layout

```
vio/
  cmd/vio/              main package: CLI entry, subcommand wiring
  internal/
    agent/              reasoning loop, context management, budgets, subagents
    llm/                Provider interface + adapters (anthropic, openai-compatible)
    transport/          Executor interface; local + ssh implementations
    inventory/          hosts.yaml loading, host groups, per-host notes
    facts/              host fact gathering (distro, init, pkg mgr, firewall backend)
    tools/              tool registry, tiers, schemas
      observe/          read-only tools
      change/           typed mutation tools (each implements Plan + Apply + Rollback)
      adapters/         distro adapters: apt/dnf/apk, ufw/nftables/firewalld, systemd/openrc
    plan/               Plan/Action model, canonical hashing, diff rendering, preconditions
    policy/             rule engine, default policy, decisions
    apply/              apply engine: backup → guard → execute → validate → verify → commit
    guard/              lockout dead-man switch, connectivity probes, config validators
    redact/             secret detection and masking, sensitive paths, secret refs
    audit/              hash-chained JSONL writer/reader/verifier
    checks/             deterministic security baseline (works without an LLM)
    runbooks/           markdown runbooks loaded on demand by the agent
    config/             config file, paths, env overrides
    ui/                 terminal rendering, prompts, --json emitters
  specs/                plan.md (this file), decisions.md
  site/                 static landing page
  assets/               logo and brand assets
  test/
    integration/        container/VM-backed tests (build tag: integration)
    evals/              agent scenario evals incl. prompt-injection cases
```

All packages live under `internal/` until an API is deliberately made public.
A public embedding API (`pkg/vio`) is a phase-4 decision.

---

## 5. Core components

### 5.1 CLI (`cmd/vio`)

Stdlib `flag` with a small subcommand dispatcher. No CLI framework.

| Command | Purpose | Mutates? |
|---------|---------|----------|
| `vio` | Interactive session (REPL): investigate, propose plans, approve inline | via approval |
| `vio ask "<q>" [-H host]` | One-shot investigation and answer | no |
| `vio check [-H host] [--fix]` | Run deterministic security baseline; `--fix` produces a plan | no (plan only) |
| `vio plan "<goal>" -H host -o plan.json` | Produce a plan file for review | no |
| `vio apply plan.json` | Execute an approved plan with guards | yes |
| `vio rollback <apply-id>` | Revert an applied plan using stored rollbacks | yes |
| `vio hosts add\|ls\|rm\|check` | Manage inventory; `check` tests connectivity + host key | no |
| `vio log [--verify]` | Show / verify the audit log | no |
| `vio init` | Create config, default policy, inventory skeleton | local only |
| `vio version` | Version, commit, build info | no |

Global flags: `-H/--host`, `-g/--group`, `--json`, `--model`, `--provider`,
`--max-tier observe|change|dangerous` (ceiling for this run), `--yes` (auto-approve up
to `change` tier only; never `dangerous`, never lockout-flagged actions without a guard).

Exit codes: `0` ok, `1` error, `2` usage, `3` policy denied, `4` approval declined,
`5` precondition drift, `6` applied but verification failed and rolled back.

### 5.2 Agent loop (`internal/agent`)

```go
type Session struct {
    ID        string
    Hosts     []inventory.Host
    Provider  llm.Provider
    Tools     *tools.Registry   // filtered by --max-tier and policy
    Budget    Budget            // turns, tokens, cost, wall time
    Messages  []llm.Message
    Proposed  *plan.Plan        // accumulated change proposals
    Audit     *audit.Log
}
```

Loop:

1. Build request: system prompt + tool schemas (cacheable prefix) + messages.
2. Stream response. Render text to the terminal as it arrives.
3. For each tool call:
   - `observe` tier → execute immediately via executor, redact, truncate, return result.
   - `change`/`dangerous` tier → **do not execute**. Call the tool's `Plan()` to produce
     an `Action` (dry-run, diff, rollback), append to `Proposed`, return the rendered
     action to the model as the tool result ("proposed, pending approval").
4. Repeat until the model ends its turn or a budget is hit.
5. If `Proposed` is non-empty: render the plan, run policy, ask for approval, then hand
   off to the apply engine. Apply results are fed back to the model so it can explain.

Context management:

- Tool output capped (default 16 KiB) with head/tail truncation; full output kept in
  a session spool and retrievable by the model via `output.read(ref, offset, limit)`.
- Compaction: when context passes ~70% of the model window, older tool results are
  summarized by a cheap model call and replaced with summaries + refs.
- Loop detection: identical tool call with identical args 3× → stop and report.

Subagents: read-only fan-out across hosts (`check` on 20 hosts in parallel). Subagents
only ever get `observe` tools. Concurrency bounded (default 8).

System prompt lives in `internal/agent/prompts/system.md` (embedded), states the tool
tiers, the data-not-instructions rule, and the house style (concise, cite evidence).

### 5.3 LLM providers (`internal/llm`)

```go
type Provider interface {
    Name() string
    Stream(ctx context.Context, req Request) (Stream, error)
}

type Request struct {
    Model     string
    System    []Block        // supports cache breakpoints
    Messages  []Message
    Tools     []ToolSpec     // name, description, JSON schema
    MaxTokens int
}
```

Adapters:

- `anthropic` — official `anthropic-sdk-go`. Prompt caching on system + tool schemas.
  Default model: `claude-sonnet-5-5`; compaction/summaries: `claude-haiku-5-5`.
- `openai` — OpenAI-compatible Chat Completions over `net/http` (covers OpenRouter,
  Ollama, vLLM, LM Studio, AI gateways). No SDK dependency.

Keys from env (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `VIO_API_KEY`) or OS keychain
later. Keys never logged, never written to audit.

### 5.4 Transport (`internal/transport`)

```go
type Executor interface {
    Run(ctx context.Context, cmd Cmd) (Result, error)        // argv, env, stdin, sudo, timeout
    ReadFile(ctx context.Context, path string, max int64) ([]byte, FileInfo, error)
    WriteFile(ctx context.Context, path string, data []byte, mode fs.FileMode) error // atomic: tmp + rename
    Stat(ctx context.Context, path string) (FileInfo, error)
    Close() error
}
```

- `local` — `os/exec`; Linux only (operator == target).
- `ssh` — `golang.org/x/crypto/ssh`:
  - Host keys: strict `known_hosts` via `x/crypto/ssh/knownhosts`. Unknown host → fail
    with the fingerprint; `vio hosts add --trust` records it explicitly. No silent TOFU.
  - Auth: ssh-agent, then key files from inventory. No password auth by default.
  - No agent forwarding, no port forwarding, no X11.
  - Connection reuse: one client per host per session, multiplexed sessions.
  - Privilege: connect as a normal user, elevate with `sudo -n`. If sudo needs a
    password, the operator is prompted once; it is held in memory only, never sent to
    the model, never logged.
  - Every `Run` has a timeout (default 60s) and an output cap.
  - Commands are passed as argv and quoted by vio, never string-built by the model.

### 5.5 Inventory (`internal/inventory`)

`~/.config/vio/hosts.yaml`:

```yaml
hosts:
  web-1:
    addr: 203.0.113.10
    port: 22
    user: deploy
    identity: ~/.ssh/id_ed25519
    tags: [prod, web]
    notes: |
      Caddy reverse proxy for app.example.com. Postgres is on db-1.
      Never restart during 09:00–17:00 SAST.
groups:
  prod: [web-1, db-1]
```

`notes` are operator-authored context given to the model. They are trusted because
they come from the operator, unlike anything read from the host.

### 5.6 Facts (`internal/facts`)

Gathered once per host per session (cached, refreshable): OS/distro/version, kernel,
arch, init system, package manager, firewall backend, sshd version, virtualization,
public/private IPs, the operator's current SSH source IP and port. Facts select the
right adapters and feed policy (e.g. "SSH port in use is 2222").

### 5.7 Tools (`internal/tools`)

```go
type Tier int
const (
    Observe Tier = iota
    Change
    Dangerous
)

type Tool interface {
    Name() string
    Description() string
    Schema() json.RawMessage
    Tier() Tier
}

type ObserveTool interface {
    Tool
    Observe(ctx context.Context, h *Host, args json.RawMessage) (Output, error)
}

type ChangeTool interface {
    Tool
    // Plan performs a dry run: reads current state, computes the diff, preconditions,
    // risk flags, and the rollback. It must not mutate the host.
    Plan(ctx context.Context, h *Host, args json.RawMessage) (plan.Action, error)
    Apply(ctx context.Context, h *Host, a plan.Action) (plan.Outcome, error)
    Rollback(ctx context.Context, h *Host, a plan.Action) error
}
```

Initial catalog:

| Tier | Tools |
|------|-------|
| observe | `host.facts`, `fs.read`, `fs.list`, `fs.stat`, `fs.grep`, `proc.list`, `net.listeners`, `net.connections`, `fw.status`, `svc.status`, `svc.list`, `log.journal`, `log.tail`, `pkg.query`, `pkg.updates`, `user.list`, `sshd.effective` (`sshd -T`), `disk.usage`, `check.run`, `output.read`, `shell.ro` (allowlisted read-only commands) |
| change | `fs.write`, `fs.patch`, `pkg.install`, `pkg.upgrade`, `svc.start/stop/restart/reload/enable/disable`, `sshd.set`, `fw.allow`, `fw.deny`, `fw.enable`, `user.add`, `user.lock`, `key.add`, `key.remove`, `autoupdates.enable`, `fail2ban.configure`, `timer.add` |
| dangerous | `shell.exec`, `fs.remove`, `pkg.remove`, `user.remove`, `fw.default_deny`, `host.reboot` |

`shell.ro` allowlist is argv-prefix based (e.g. `df`, `free`, `uptime`, `ss -tlnp`,
`systemctl status`, `journalctl --no-pager`), rejects shell metacharacters, and runs
without a shell. Anything else is `shell.exec` (dangerous).

Adapters (`tools/adapters`) hide distro differences: `pkg` → apt/dnf/apk,
`fw` → ufw/nftables/firewalld, `svc` → systemd/openrc. Support order:
Ubuntu/Debian → RHEL family (Rocky/Alma/Fedora) → Alpine.

### 5.8 Plans (`internal/plan`)

```go
type Plan struct {
    ID        string            // p-<short hash>
    CreatedAt time.Time
    Goal      string            // operator's request, verbatim
    Hosts     []string
    Actions   []Action
    Hash      string            // sha256 of canonical JSON (excluding Hash/Approval)
    Approval  *Approval
}

type Action struct {
    ID            string
    Host          string
    Tool          string
    Args          json.RawMessage
    Tier          tools.Tier
    Summary       string           // human one-liner
    Diff          string           // unified diff or before/after state
    Risk          []RiskFlag       // lockout, downtime, data_loss, irreversible
    Preconditions []Precondition   // e.g. file sha256, pkg version, service state
    Rollback      *RollbackSpec    // nil only if Risk contains irreversible
    Verify        []Probe          // post-apply checks
    Taint         []TaintSource    // args derived from host data
    DependsOn     []string
}

type Approval struct {
    PlanHash   string
    Operator   string
    At         time.Time
    MaxTier    tools.Tier
}
```

Plans serialize to JSON (`vio plan -o plan.json`) so they can be reviewed, committed,
or approved by a second person. `vio apply` recomputes the hash and refuses on mismatch.

### 5.9 Policy (`internal/policy`)

Every action is evaluated before approval and again right before execution.

```go
type Decision int // Allow, Confirm, Deny
type Rule interface {
    ID() string
    Evaluate(ctx EvalContext, a plan.Action) (Decision, string)
}
```

Most restrictive decision wins. Default policy (built in, extendable):

- **deny** closing or restricting the SSH port the operator is connected on unless an
  alternative access path is verified in the same plan.
- **deny** disabling the operator's login user or removing their key.
- **deny** `PasswordAuthentication no` if the operator authenticated by password.
- **deny** `fs.remove` outside allowlisted paths (`/tmp`, `/var/tmp`, app-defined dirs).
- **deny** writes to `/boot`, `/etc/fstab`, bootloader configs (phase 2; later: confirm).
- **confirm** anything `dangerous`, anything with `irreversible`, anything tainted.
- **confirm** actions on hosts tagged `prod` when `--yes` is used.
- **allow** the rest, subject to `--max-tier`.

Phase 1–2: rules in Go. Phase 3: user rules in a small declarative format evaluated with
CEL (`cel-go`), stored at `~/.config/vio/policy.yaml`. See open question Q1.

### 5.10 Apply engine (`internal/apply`)

Deterministic. Per action, in dependency order:

1. **Re-check policy** against the approved plan hash.
2. **Check preconditions.** Drift → abort with exit code 5 (nothing changed yet).
3. **Backup.** Files to `/var/lib/vio/backups/<apply-id>/` (mode 0700, root-owned);
   package versions and service states recorded.
4. **Arm guard** if the action has the `lockout` risk (see 5.11).
5. **Execute** `Apply()`.
6. **Validate** with native validators (`sshd -t`, `nginx -t`, `caddy validate`,
   `nft -c -f`, `visudo -c`) *before* reload/restart where the tool supports it.
7. **Reload/restart** if needed.
8. **Verify** with probes (service active, port listening, fresh SSH login, HTTP 200).
9. **Disarm guard** on success; on failure → `Rollback()` → verify again.
10. **Record** the outcome in the audit log.

Failure policy: stop at the first failed action and roll back that action. Earlier
successful actions stay applied unless `--atomic` is set, in which case all are rolled
back in reverse order. `vio rollback <apply-id>` can revert later.

### 5.11 Lockout guard (`internal/guard`)

The feature that makes vio safe to point at a remote box.

```
arm:     upload /var/lib/vio/guards/<id>/revert.sh (restores backups, reloads services)
         systemd-run --unit=vio-guard-<id> --on-active=120s /var/lib/vio/guards/<id>/revert.sh
         (fallback without systemd: setsid nohup sh -c 'sleep 120 && revert.sh' &)
apply:   change + validate + reload
probe:   open a NEW ssh connection (new TCP, full auth) and run `true`
         and, if relevant, check the service port from the operator side
disarm:  success → systemctl stop vio-guard-<id>.timer; remove guard dir
         failure → do nothing; host self-reverts at T+120s; vio waits, reconnects,
                   confirms revert, reports exit code 6
```

Guard window is configurable (min 30s, default 120s). The probe always uses a fresh
connection because an existing session can survive a broken sshd or firewall config.

### 5.12 Redaction (`internal/redact`)

Applied to every byte of tool output before it reaches the model or the audit log.

- Pattern detectors: PEM private keys, OpenSSH keys, AWS/GCP/Azure keys, GitHub/GitLab
  tokens, Slack tokens, JWTs, connection strings with credentials, `KEY=/TOKEN=/SECRET=/
  PASSWORD=` assignments, high-entropy strings in assignment context.
- Sensitive paths: `/etc/shadow`, `/etc/gshadow`, `~/.ssh/id_*`, `*.pem`, `*.key`,
  `.env*`, `/etc/ssl/private/*` → content replaced by a structural summary
  (line count, key names, no values) unless the operator passes `--reveal` for that run.
- Replacement format: `[REDACTED:<kind>:<8-char hash>]` so the model can tell two
  secrets apart and refer to them without seeing them.
- Secret refs: change tools accept `secret://<name>`; values are resolved locally from
  env / keychain by the executor, never by the model.

Redaction is fail-closed: a detector error masks the whole output.

### 5.13 Audit log (`internal/audit`)

- Location: `<state dir>/audit.jsonl` (`~/.local/state/vio/` on Unix,
  `%LocalAppData%\vio\` on Windows). Optional mirror on host at
  `/var/lib/vio/audit.jsonl`.
- One JSON object per line: `seq`, `ts`, `session`, `host`, `kind`
  (`session.start|observe|propose|policy|approve|apply|verify|rollback|session.end`),
  `tool`, `args` (redacted), `result_digest`, `exit`, `prev` (sha256 of previous line).
- `vio log --verify` checks the hash chain. Truncation or edits are detectable.
- Full outputs are stored by digest in the session spool, not inline.

### 5.14 Security baseline (`internal/checks`)

Deterministic checks that run with **no LLM**, so `vio check` is useful offline, in CI,
and as ground truth for the agent.

```go
type Check struct {
    ID       string   // e.g. VIO-SSH-001
    Title    string
    Severity Severity // info, low, medium, high, critical
    Applies  func(facts.Facts) bool
    Run      func(ctx context.Context, h *Host) (Finding, error)
    Fix      *FixTemplate // tool + args to propose a plan action
}
```

Initial set (CIS-inspired, VPS-focused): SSH root login, password auth, key-only
access, sshd crypto settings; firewall active + default deny inbound; listening services
exposed on public interfaces; pending security updates; unattended upgrades; fail2ban /
equivalent; users with UID 0; users with empty passwords; sudoers NOPASSWD audit;
world-writable files in system paths; SUID inventory; time sync; swap; disk headroom;
Docker socket exposure; Docker containers with published ports bypassing ufw.

### 5.15 Runbooks (`internal/runbooks`)

Markdown files with frontmatter (`name`, `description`, `applies_to`). Built-in
runbooks are embedded (`harden-ubuntu`, `disk-full`, `high-load`, `tls-renew`); user
runbooks live in `~/.config/vio/runbooks/`. The agent sees only names + descriptions
and loads a body on demand. Runbooks guide reasoning; they grant no permissions.

### 5.16 Config (`internal/config`)

`~/.config/vio/config.yaml` (`os.UserConfigDir()`):

```yaml
provider: anthropic
model: claude-sonnet-5-5
small_model: claude-haiku-5-5
max_tier: change
guard_window: 120s
budget:
  max_turns: 40
  max_cost_usd: 2.00
output:
  color: auto
redact:
  extra_patterns: []
```

Precedence: flags > env (`VIO_*`) > config file > defaults.

### 5.17 UI (`internal/ui`)

- Streaming plain text. Status lines prefixed `●`, findings `✗/✓`, plans as tables.
- Colors via ANSI only when stdout is a TTY and `NO_COLOR` is unset.
- `--json`: newline-delimited events (same schema as audit kinds) for scripts and CI.
- Approval prompt shows plan hash, risk flags, taint sources, and guard window.

---

## 6. Prompt-injection defense in depth

1. **Structural separation.** Tool results are wrapped with provenance
   (`<tool_output host="web-1" tool="log.tail" trust="untrusted">`), and the system
   prompt states that tool output is data.
2. **Capability limits.** In the reasoning loop the model can only observe. Mutation
   requires a plan that a human (or explicit `--yes` within tier) approves.
3. **Taint tracking.** When a change action's argument (an SSH key, username, URL,
   package name, IP) appears in host-derived output but not in operator input or
   inventory notes, the action is marked tainted and requires explicit confirmation,
   with the source shown.
4. **Policy.** Hard denies apply regardless of what the model or approver says
   (except via a deliberate policy file change).
5. **Evals.** A standing suite of injection scenarios (`test/evals/injection/*`) must
   pass before every release.

---

## 7. Example flows

### 7.1 Harden a new VPS

```
$ vio check -H web-1 --fix
● web-1  ubuntu 24.04 · systemd · apt · ufw (inactive)
  ✗ high     VIO-SSH-002  PasswordAuthentication yes
  ✗ high     VIO-FW-001   firewall inactive; 4 ports listening publicly
  ✗ medium   VIO-PKG-001  23 security updates pending
  ✓ ...
plan p-7f3a91 · 3 actions · risk: lockout, downtime
  1  sshd.set PasswordAuthentication=no         guard 120s · rollback ✓
  2  fw.allow 22,80,443/tcp + fw.enable          guard 120s · rollback ✓
  3  pkg.upgrade --security                      rollback: version pins
approve plan p-7f3a91? [y/N] y
● guard armed (vio-guard-a1) · applying 1/3 … validated (sshd -t) · fresh login ✓ · disarmed
● guard armed (vio-guard-a2) · applying 2/3 … fresh login ✓ · :443 reachable ✓ · disarmed
● applying 3/3 … 23 packages upgraded
✓ applied p-7f3a91 · audit seq 1042–1061
```

### 7.2 Investigate

```
$ vio ask -H web-1 "why is the site slow since this morning?"
```

The agent reads load, memory, disk, journal, Caddy/nginx logs, and DB connections,
then answers with evidence and, if useful, a proposed plan.

---

## 8. Security of vio itself

- Dependencies kept minimal; every new one recorded in `specs/decisions.md`.
- CI: `go vet`, `staticcheck`, `govulncheck`, `go test -race`.
- Builds: `CGO_ENABLED=0 -trimpath -ldflags "-s -w"`, reproducible.
- Releases via GoReleaser: linux/darwin/windows × amd64/arm64, checksums, SBOM,
  keyless signatures (cosign) and GitHub artifact attestations.
- No telemetry. The only network calls are SSH to inventory hosts and the configured
  model endpoint.
- Files written by vio on the operator machine are `0600`/`0700`.

Planned direct dependencies:

| Module | Why |
|--------|-----|
| `golang.org/x/crypto/ssh` (+ `knownhosts`, `agent`) | SSH transport |
| `github.com/anthropics/anthropic-sdk-go` | Anthropic provider |
| `go.yaml.in/yaml/v3` | Config and inventory |
| `golang.org/x/term` | TTY detection, password prompt |
| `github.com/google/cel-go` (phase 3) | User policy rules |

---

## 9. Testing strategy

| Layer | How |
|-------|-----|
| Unit | Table-driven tests per package. `transport.Fake` records argv and serves canned files. |
| Plan golden tests | Each change tool: fixture state → `Plan()` → golden JSON + diff. |
| Agent loop | `llm.Fake` scripts model turns deterministically; asserts tool calls, budgets, loop detection. |
| Redaction | Corpus of real-shaped secrets + false-positive corpus. Fuzz tests. |
| Policy | Table of actions × facts → expected decision. |
| Integration | `//go:build integration`: Docker containers (Debian/Ubuntu/Rocky/Alpine) with sshd. |
| Lockout | VM-based (systemd required): deliberately break sshd/firewall, assert auto-revert and exit 6. Nightly in CI. |
| Evals | Scenario suite against real models: findings accuracy, zero policy violations, injection resistance. Tracked over time. |

Rule: no change tool merges without golden tests, a rollback test, and an integration test.

---

## 10. Budgets

| Metric | Target |
|--------|--------|
| Binary size | < 20 MB |
| `vio --help` / `vio version` | < 20 ms |
| `vio check` on one host (no LLM) | < 5 s |
| Host footprint | nothing installed; only `/var/lib/vio` state |
| Default session cost cap | $2.00 (configurable) |

---

## 11. Roadmap

Each phase has an exit criterion; a phase is done when it is met, not when code exists.

### Phase 0 — Foundations
- Move `main.go` → `cmd/vio/main.go`; subcommand dispatcher; `vio version`.
- `config`, `inventory`, `transport` (local + ssh with strict known_hosts), `audit`.
- `vio init`, `vio hosts add|ls|check`, `vio log --verify`.
- CI: vet, staticcheck, govulncheck, race tests. GoReleaser snapshot builds.
- **Exit:** `vio hosts check web-1` connects with a verified host key and is audited.

### Phase 1 — Read-only agent
- `llm` (anthropic + openai-compatible), `agent` loop, budgets, compaction.
- `facts`, all observe tools, `redact`, `shell.ro`.
- `checks` baseline + `vio check` (no LLM).
- `vio ask`, interactive `vio` (observe-only).
- Injection eval suite v1.
- **Exit:** full, accurate audit and Q&A on a fresh Ubuntu 24.04 VPS; no secrets in
  model traffic (verified by redaction tests on captured transcripts).

### Phase 2 — Plan & apply
- `plan`, `apply`, `guard`, backups, preconditions, verify probes, `vio rollback`.
- Change tools: `sshd.set`, `fw.*` (ufw), `pkg.*` (apt), `svc.*`, `fs.write/patch`,
  `user.*`, `key.*`, `autoupdates.enable`, `fail2ban.configure`.
- `vio plan`, `vio apply`, `vio check --fix`.
- Built-in Go policy rules + taint tracking.
- **Exit:** harden a fresh VPS end to end; lockout suite passes (bad sshd config and
  firewall rule both auto-revert within the guard window).

### Phase 3 — Policy & fleet
- User policy (CEL), `--json` event stream, non-interactive mode for CI.
- Groups and parallel fan-out; adapters for dnf/firewalld/nftables, apk/openrc.
- Plan approval by a second operator (approve file workflow).
- **Exit:** `vio check -g prod --json` in CI; policy file blocks a scripted unsafe plan.

### Phase 4 — Ecosystem
- Tools for Docker/Compose, Caddy/nginx, TLS certificates, backups (restic), Postgres basics.
- MCP: expose vio's observe tools as an MCP server; consume MCP servers for cloud APIs.
- `vio watch`: scheduled drift/baseline checks with notifications (webhook/email).
- Decide on a public embedding API (`pkg/vio`).

### Phase 5 — Optional on-host mode
- `vio agentd`: optional on-host daemon for hosts without inbound SSH (outbound-only
  connection, same plan/policy/audit model). Agentless remains the default.

---

## 12. Open questions

- **Q1. Policy language.** Go-only rules, CEL, or Rego? Leaning CEL: small, sandboxed,
  pure Go, well-suited to "decision over a struct".
- **Q2. Keychain.** Use OS keychains for API keys and sudo passwords (adds a dependency)
  or env-only?
- **Q3. Interactive UI.** Plain line-based REPL vs. light raw-mode line editor. Leaning plain.
- **Q4. Plan approval by others.** Signed approvals (ssh-keygen -Y sign) for team use?
- **Q5. Host-side audit mirror.** On by default, or opt-in?
- **Q6. Model routing.** Use the small model for observe-heavy subagents by default?
