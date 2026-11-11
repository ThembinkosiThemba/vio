# Security Policy

vio holds SSH access to servers, so we take security reports seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Report privately via GitHub's
[private vulnerability reporting](https://github.com/ThembinkosiThemba/vio/security/advisories/new).

Include what you can: affected version/commit, a description, reproduction steps,
and the impact you expect. We aim to acknowledge within 72 hours and to agree on a
disclosure timeline with you.

## Scope

In scope — anything that breaks vio's safety model, for example:

- A change reaching a host without an approved plan, or bypassing policy.
- Secrets (keys, passwords, tokens) reaching the model provider or the audit log.
- Prompt injection from host data that results in a mutation without the expected
  confirmation.
- Lockout guard failing to revert, or a probe reporting success incorrectly.
- SSH host-key verification bypasses.
- Tampering with the audit log going undetected by `vio log --verify`.

Out of scope: issues requiring an already-compromised operator machine, and
behaviour of third-party model providers.

## Supported versions

vio is pre-1.0. Only the latest release receives security fixes.
