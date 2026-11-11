# Contributing to vio

Thanks for helping. vio is a tool that touches production servers, so the bar for
safety is high and the bar for complexity is low.

## Before you start

1. Read [specs/plan.md](specs/plan.md), especially the design principles (§1) and the
   roadmap (§11). Work that belongs to a later phase will likely wait.
2. Read the safety invariants in [AGENTS.md](AGENTS.md). PRs that weaken them won't merge.
3. For anything bigger than a bug fix, open an issue first so we can agree on the approach.

## Development

```sh
git clone https://github.com/ThembinkosiThemba/vio
cd vio
go build ./...
go test -race ./...
go vet ./...
```

Integration tests need Docker on Linux: `go test -tags integration ./test/integration/...`

## Pull requests

- Keep PRs small and focused; one concern per PR.
- `gofmt`, `go vet`, `staticcheck`, and tests must pass.
- New change tools need golden plan tests, a rollback test, and an integration test.
- New dependencies need a short justification appended to
  [specs/decisions.md](specs/decisions.md).
- Write commit messages in the imperative ("Add sshd.set rollback"), and explain *why*
  in the body when it isn't obvious.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please don't file public issues for vulnerabilities.

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
