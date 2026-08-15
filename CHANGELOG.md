# Changelog
## 1.1.0 - 2026-08-15
Hardened the verification boundary in response to external adversarial
review. Certificate schema compatibility: v1 (arcifact-certificate/1).

### Security
- Certificate verifier now returns a verdict MATRIX, not a single
  GREEN flag. VALID requires every mandatory check for the profile;
  anything unavailable is INCOMPLETE/UNKNOWN, never VALID.
- The published closed JSON Schema is now ENFORCED (jsonschema when
  available; a bounded builtin check otherwise).
- Issuer authenticity: signatures verify against an out-of-band
  Arcifact key by key_id. A key embedded in a certificate is never
  trusted alone. Absent/unverifiable signatures fail closed for the
  issued profile; signature stripping is caught.
- Manifest roots use an explicit arcifact-manifest-set/1 member list;
  directory globbing removed.
- Witness rejects empty artifact lists, unknown artifact types, and
  workflows whose needs reference nonexistent jobs.
- Full SHA-256 comparison restored in bank integrity (display prefix
  kept separately).

### Tests and CI
- 23 real adversarial tests with committed public fixtures; no no-ops.
  Signature tests skip explicitly without pynacl. CI fails if fixtures
  are missing. Actions pinned by commit SHA.

### Docs
- Canonical schema at manifests/certificate.schema.v1.json (site and
  kit share the bytes). Threat model added. Issuer key and root policy
  documented. "source-available" replaces "open".

### Deprecates
- 1.0.0 (pre-hardening). Use 1.1.0 for any verification.
