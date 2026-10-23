# Design and trust boundaries

Review exported Windows service command lines, accounts and operator-supplied write evidence without changing services.

- Conservative executable parsing separates arguments from unquoted paths with spaces.
- Ambiguous executable candidates are matched against explicit write evidence; missing ACL evidence stays unconfirmed.
- Unknown environment-variable/relative paths remain inconclusive; disabled services retain context.
- Reports retain source SHA-256, reasons and recommendations in JSON/Markdown.

Snapshot-only review: it does not measure effective ACLs, test candidate existence, start services or prove privilege escalation. Driver/script command lines outside the supported executable model remain unknown.

The source snapshot is evidence supplied by the operator, not remote attestation. A metadata flag or heuristic is not proof of an attack. Tests use fixtures constructed by this repository and do not contact external targets. Do not execute or extract untrusted samples as a way to use this tool.
