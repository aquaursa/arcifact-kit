# Measurement Protocol

This document states what an Arcifact number means. It is
deliberately brief; the full protocol, including adversarial
hardening procedures and construction methodology, is available to
qualified partners under agreement and will be published formally in
due course.

## Preregistration

Every published number was scored against a bar registered before
the run that produced it. Misses are retained in the internal lab
record with mechanism analyses; no bar is adjusted after the fact.
Reference numbers in `BASELINES.md` therefore come in one flavor
only: predictions that were allowed to fail and did not.

## Adversarial hardening

Banks ship only after adversarial review designed to defeat scoring
without the target competence, including screens for surface
shortcuts, robustness checks under item re-rendering, positional
controls, and explicitly computed chance floors. At least one
compiled domain has been rejected by these gates and is absent from
the kit for that reason. Procedure details are withheld here by
policy.

## Envelope reporting

Certificates report the regime in which a score was earned, not a
single flattering aggregate. Where competence is banded, the band
boundaries and per-band numbers are part of the certificate, and
out-of-envelope behavior is reported as such: honest incapacity is
distinguished from error.

## Fabrication semantics

The kit's headline metric is the fabrication rate: the share of
named answers that name an observation the gold itself never names.
It does not measure style, verbosity, or rubric agreement; it
measures whether the system asserted the existence of evidence that
does not exist.

## What is deliberately absent

Item generators, construction tooling, pipeline internals, and
training data are not in this repository, and the license forbids
reconstructing them. Banks are frozen artifacts with published
digests; the verification path is public while the manufacturing
path is not.
