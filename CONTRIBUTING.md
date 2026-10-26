# Contributing to ReplayProof

ReplayProof is a Python 3.10+ prototype for verifying observable business-state invariants after webhook deliveries.

## Quick start

```bash
python -m unittest discover -s tests -v
python -m demo.webhook_server --mode vulnerable
# In another terminal:
python -m replayproof.cli examples/staging.json --out report
```

## Pull requests

- Open an issue before substantial design changes.
- Keep pull requests focused and include tests for new delivery patterns.
- Document expected business-state assertions and the limitations of any probe.
- Never include real credentials, customer data, actual payment identifiers, or production URLs.
- Do not run replay tests against systems you do not own or lack explicit permission to test.

By contributing, you agree that your contributions are licensed under the repository's MIT License.

## Scope

This project is a local/staging testing tool, not a production payment processor, vulnerability scanner, Stripe certification, or guarantee of exactly-once processing.
