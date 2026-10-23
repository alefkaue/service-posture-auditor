# Windows service posture

Offline snapshot review; no services started, permissions changed or exploitation performed.

Input SHA-256: `dc0cfb4a6ed53b4bf1fd88b95924539ca1c3beb44ddd4c1be6a506a11061f7c0`

| Service | Account | Startup | Findings |
|---|---|---|---|
| SyntheticQuoted | NT AUTHORITY\LocalService | Auto | 0 |
| SyntheticAmbiguous | LocalSystem | Auto | 1 |
| SyntheticUnknown |  | Manual | 2 |

## SyntheticQuoted

Evidence: Synthetic, not a machine scan

## SyntheticAmbiguous

Evidence: Synthetic candidate-write attestation; not an exploit
- **high / UNQUOTED_EXECUTABLE_PATH:** Unquoted spaced path with operator-supplied write evidence for an actual ambiguous candidate. Quote only the executable, preserve arguments, validate ACLs and test changes through normal change management. This observation is not proof of privilege escalation.

## SyntheticUnknown

Evidence: Synthetic unresolved environment
- **review / PATH_UNRESOLVED:** Missing path or environment variables require source-machine resolution. Collect the expanded executable path from the owning machine; do not expand using the analyst's environment.
- **review / ACCOUNT_UNKNOWN:** Service account was not collected. Collect StartName before making a privilege-impact claim.
