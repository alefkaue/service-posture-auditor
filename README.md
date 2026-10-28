# Windows Service Posture Auditor

**Portfolio area:** [Cloud/Infrastructure](https://github.com/alefkaue#cloudinfraestrutura) · **Context:** Personal project

**C# · offline defensive analysis · original personal portfolio project**

Review exported Windows service command lines, accounts and operator-supplied write evidence without changing services.

[Português](README.pt-BR.md) · [Design and limits](docs/design.md) · [Executed example output](docs/demo-output.txt)

## Run and test

.NET 10 SDK. Uses only the standard framework; no NuGet package dependencies. Tests use a dependency-free executable regression harness with a nonzero failure exit, not a fabricated dotnet-test count.

```console
dotnet run --project tests/ServicePosture.Tests -c Release
dotnet run --project src/ServicePosture -c Release -- examples/services.json examples/output
```

## Features

- Conservative executable parsing separates arguments from unquoted paths with spaces.
- Ambiguous executable candidates are matched against explicit write evidence; missing ACL evidence stays unconfirmed.
- Unknown environment-variable/relative paths remain inconclusive; disabled services retain context.
- Reports retain source SHA-256, reasons and recommendations in JSON/Markdown.

## Evidence and limits

Snapshot-only review: it does not measure effective ACLs, test candidate existence, start services or prove privilege escalation. Driver/script command lines outside the supported executable model remain unknown.

The committed examples/output files come from synthetic local runs. They are not customer results,
professional assessments or demonstrations against third-party systems. Input paths and archive names
can still be sensitive: keep real reports private. No account, service or network configuration is changed.

## Engineering

Parsing, decisions and output are separate from CLI argument handling. Tests cover positive cases,
ambiguous evidence and malformed data. GitHub Actions builds/tests on Windows and Linux with
read-only repository permissions and actions pinned by commit. See docs/tests.txt for the recorded local run.

Built by Alef Kaue Santos Nunes with AI assistance. This does not claim professional experience or
independent vulnerability discovery. MIT covers original code and documentation.

## Reference

- [Official format/API reference](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-query_service_configw)
