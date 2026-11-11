<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="site/img/logo-white.png">
    <img src="site/img/logo-black.png" height="64" alt="vio">
  </picture>
</p>

<p align="center">
  <b>A tiny, safety-first agent that runs and secures your servers.</b><br>
  Single Go binary · agentless over SSH · plans before it touches anything
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-7c3aed"></a>
  <img alt="Status: pre-alpha" src="https://img.shields.io/badge/status-pre--alpha-orange">
  <img alt="Go 1.26+" src="https://img.shields.io/badge/go-1.26+-00ADD8">
</p>

---

> **Status: pre-alpha.** vio is being built in the open. The architecture is in
> [specs/plan.md](specs/plan.md); nothing here is ready for production servers yet.

## What is vio?

vio is a command-line agent for Linux servers. Ask it questions, have it audit
a box, and let it fix what it finds. It always shows you a reviewable plan first,
and it can undo every step.

Coding agents work in a git repo, so any mistake can be reverted. Live servers can't
be reverted that way, so vio is built around one rule:

**The model proposes, the code disposes.**

The LLM investigates using read-only tools. Every change is a typed action with a
diff, a rollback, and risk flags. Changes go through a deterministic policy engine and
need your approval. They run under a guard that auto-reverts if you lose access, and
every step is recorded in a tamper-evident audit log.

```text
$ vio check -H web-1 --fix
● web-1  ubuntu 24.04 · systemd · apt · ufw (inactive)
  ✗ high     VIO-SSH-002  PasswordAuthentication yes
  ✗ high     VIO-FW-001   firewall inactive; 4 ports listening publicly
  ✗ medium   VIO-PKG-001  23 security updates pending
plan p-7f3a91 · 3 actions · risk: lockout, downtime
  1  sshd.set PasswordAuthentication=no         guard 120s · rollback ✓
  2  fw.allow 22,80,443/tcp + fw.enable          guard 120s · rollback ✓
  3  pkg.upgrade --security                      rollback: version pins
approve plan p-7f3a91? [y/N] y
● guard armed · applying 1/3 … sshd -t ✓ · fresh login ✓ · disarmed
● guard armed · applying 2/3 … fresh login ✓ · :443 reachable ✓ · disarmed
● applying 3/3 … 23 packages upgraded
✓ applied p-7f3a91 · audit seq 1042–1061
```

## Features

- **Agentless.** Works on any Linux host you can SSH into. Nothing to install on the host.
- **Plan → approve → apply.** Changes are typed, diffed, hashed, and approved as a whole plan.
- **Lockout protection.** SSH and firewall changes arm a dead-man switch. If a *fresh*
  SSH login fails afterwards, the host reverts itself.
- **Policy as code.** Hard rules (e.g. "never close the port I'm connected on") are
  enforced in code, not in a prompt.
- **Secrets stay local.** Output is redacted before it reaches the model.
- **Prompt-injection aware.** Host data is treated as data. Change arguments that came
  from host output are flagged and need explicit confirmation.
- **Deterministic baseline.** `vio check` runs a security baseline with no LLM, so it
  also works offline and in CI.
- **Audit log.** Every observation, approval, and command is written to an append-only,
  hash-chained log.
- **Any model.** Anthropic, any OpenAI-compatible endpoint (OpenRouter, Ollama, vLLM),
  or local models.
- **Small and fast.** One static binary for Linux, macOS, and Windows.

## Install

**macOS / Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/ThembinkosiThemba/vio/main/site/install.sh | sh
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/ThembinkosiThemba/vio/main/site/install.ps1 | iex
```

Then run `vio`. The installers download the latest release, verify its SHA-256
checksum, and put the binary on your PATH. Set `VIO_VERSION=v0.1.0` to pin a version.

> No release is tagged yet. Until then, build from source (Go 1.26+):
> `go install github.com/ThembinkosiThemba/vio/cmd/vio@latest`

## Usage (planned)

```sh
vio init                                   # config, default policy, inventory
vio hosts add web-1 --addr 203.0.113.10 --user deploy --trust
vio ask -H web-1 "why is disk usage at 95%?"
vio check -H web-1                         # security baseline, no LLM
vio check -H web-1 --fix                   # baseline + proposed fix plan
vio plan -H web-1 "install fail2ban for sshd" -o plan.json
vio apply plan.json
vio rollback <apply-id>
vio log --verify
```

## How it works

```text
prompt ─▶ agent loop ⇄ model         (observe tools only)
              │
              ▼ proposed changes
            plan ─▶ policy ─▶ your approval ─▶ apply engine
                                               backup → guard → apply → validate
                                               → verify (fresh login) → disarm
                                               └─▶ audit log
```

Read the full design in [specs/plan.md](specs/plan.md).

## Roadmap

| Phase | Focus |
|-------|-------|
| 0 | Foundations: CLI, config, inventory, SSH transport, audit log |
| 1 | Read-only agent: `vio ask`, `vio check`, redaction |
| 2 | Plan & apply: typed change tools, lockout guard, rollback |
| 3 | Policy files, fleets, JSON output, more distros |
| 4 | Docker, Caddy/nginx, TLS, MCP, scheduled drift checks |

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the safety
invariants in [AGENTS.md](AGENTS.md).

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
