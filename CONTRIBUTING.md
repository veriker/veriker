# Contributing to Veriker

Issues and pull requests are welcome. Veriker is a verification tool, so the
bar is correctness and honesty about scope — a check that can be fooled is
worse than no check.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
1.1 instead of a Contributor License Agreement. You keep the copyright to your
contribution; you certify that you have the right to submit it under the
project's Apache-2.0 license.

Sign off every commit:

```bash
git commit -s -m "your message"
```

This appends a `Signed-off-by: Your Name <you@example.com>` line, which is your
DCO certification. We do **not** use a copyright-assignment CLA.

## Before you open a pull request

- Install from source with the dev extras and run the suite:
  `pip install -e ".[dev]" && pytest`. (A plain `pip install veriker` gives you
  the runtime command only — it does not carry the `examples/` pilots or the
  test tooling, so you need the source checkout to contribute.)
- New pilots follow the **Current** spec-pinned wiring (spec consumed in the
  pilot's own `verify.py`, exercised by its `tests/` — no standalone driver).
- Keep claims honest: a pilot's README states the exact property it
  demonstrates and the explicit limits of that claim. Synthetic data stays
  labeled synthetic; "evidence for a property" is never written up as
  "compliant with a standard."
- The core verify path is offline and stdlib-only. Changes that add a
  third-party import to that path will fail the import-boundary ratchet — by
  design.

## Reporting security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
