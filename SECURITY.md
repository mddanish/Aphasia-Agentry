# Security Policy

Aphasia Agentry **ships intentionally vulnerable code** (the fixture in `fixture/`). That
code is a test target, not a defect — do not report it as a vulnerability.

## Reporting a vulnerability in Aphasia Agentry itself

A real issue is one in the **engine** (`engine/`) — for example, the tool mirror executing a
mutating call it should have blocked, a sandbox-inert guarantee failing, a canary that is not
per-run unpredictable, or evidence that can be forged.

- Please report privately via GitHub's **"Report a vulnerability"** (Security Advisories) on
  the repository, or by the contact listed there.
- Do not open a public issue for a security report.
- Include a minimal reproduction and the commit/version.

We aim to acknowledge within a few business days.

## Scope

In scope: the `engine/` package and the safety invariants (record-only mirror, sandbox-inert
fixture, per-run canaries, append-only evidence).
Out of scope: the deliberately-vulnerable fixture behaviours, and any deployment that exposes
the fixture to a network (don't).
