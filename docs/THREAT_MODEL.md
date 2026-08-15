# What an Arcifact certificate does and does not prove
This document states the trust boundary precisely so no reader
mistakes self-consistency for authenticity.

## The verifier establishes
- Integrity: the certificate body is unchanged since sealing (the
  self-seal recomputes).
- Schema conformance: the certificate matches the published closed
  v1 schema (types, bounds, no unknown fields, valid dates,
  issued < expires).
- Issuer authenticity, for the issued profile: the signature
  verifies against the Arcifact public key supplied OUT OF BAND
  (--issuer-keys / --issuer-key), by key_id. A key embedded in the
  certificate is never trusted on its own.
- Evidence, when supplied: each published bank matches its full
  SHA-256; the manifest root recomputes from an explicit member
  list; the certificate is not in a supplied revocation list; it is
  unexpired.
- Fail-closed: an absent or unverifiable signature on an issued
  certificate yields INCOMPLETE or INVALID, never VALID. Signature
  stripping is caught because the issued profile requires a verified
  signature.

## The verifier does NOT by itself establish
- That the named model generated the responses, or that a specific
  configuration was used.
- That the run was the first or only run, or that all failed runs
  were retained.
- That a threshold commitment existed before the run, or that a
  held-out bank existed in final form before evaluation.
- That the model never saw the bank or its source corpus.
- That the public response file is the one originally scored.
These are properties of the ISSUANCE process, not of a static
certificate. They are addressed by the append-only run-commitment
record on the roadmap, which binds bank, threshold, scorer bytes,
run configuration, response digest, result, certificate id, issuer
signature and revocation state. Until that record is public, the
deliverable is described as an Arcifact evidence report with a
reproducible public scoring bundle, not a cryptographic certificate
authority.

## Profiles
- draft: seal + schema only; no issuance claim.
- report: seal + schema + (optional) evidence; no signature required.
- issued: all of the above AND a verified Arcifact signature, full
  bank digests, current expiry. Only this profile returns VALID.
