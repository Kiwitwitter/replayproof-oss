# ReplayProof

**Open-source webhook reliability testing that verifies business outcomes, not just HTTP responses.**

ReplayProof is a lightweight, Python 3.10+ CLI for checking **observable business invariants** after synthetic webhook deliveries in your **own authorized staging environment**. It tests whether duplicate, concurrent, retried, or out-of-order events lead to unexpected downstream effects.

> Early prototype. Not a hosted service, production certification, or proof of exactly-once delivery.

## What it tests

- Repeated delivery of the same event identifier
- Concurrent duplicate deliveries
- Retrying after a failed acknowledgement or partial processing
- Out-of-order event sequences
- Explicit expected business state and maximum side-effect counts
- Optional Stripe-style HMAC signing with a **test-only** secret
- Machine-readable JSON and human-readable Markdown reports

**A successful HTTP response does not prove an effect happened exactly once.** ReplayProof requires a read-only business-state probe and assertions. When a result cannot be observed, it reports **INCONCLUSIVE**.

## Quick start

No third-party runtime dependencies.

```bash
# Terminal 1: local intentionally broken demo
python -m demo.webhook_server --mode vulnerable

# Terminal 2: execute local example
python -m replayproof.cli examples/staging.json --out report
```

Restart the demo with `--mode safe` and repeat the command to compare results. The CLI writes `report.json` and `report.md`.

Or run an automated local demo:

```bash
python -m demo.quickstart
```

Run unit tests:

```bash
python -m unittest discover -s tests -v
```

## Use against your own staging system

Create a JSON manifest with the following fields:

- `target`: test-only webhook handler URL
- `probe`: read-only endpoint returning observable business state
- `reset`: fixture reset endpoint run before each scenario
- `cases`: `duplicate`, `parallel-duplicate`, `retry`, or `reorder`
- `expected_state` and/or `max_side_effect_delta`: assertions on probe fields

See [examples/staging.json](examples/staging.json) for a complete working local example.

Remote delivery is **off by default**. For an HTTPS staging environment you own or are explicitly authorized to test:

```bash
python -m replayproof.cli examples/my-staging.json \
  --allow-remote --i-own-this-staging-endpoint --out report
```

The target, reset, and probe must share a hostname; redirects are not followed. The tool caps total test requests. These checks do not authorize testing other people's systems and do not fully eliminate SSRF or DNS-rebinding risks. Do not use production endpoints, real payments, customer credentials, or live customer data.

Optional test signature:

```bash
export RP_TEST_SECRET=whsec_test_only
python -m replayproof.cli examples/staging.json --stripe-secret-env RP_TEST_SECRET
```

## Scope and limitations

- Tests only scenarios and invariants you explicitly configure.
- Requires access to a safe business-state probe to establish outcomes.
- The sample webhook format is Stripe-inspired, not a full Stripe or Shopify integration.
- No production endpoint scanning or automatic remediation.
- No hosted service, real customer integrations, or payment processing.
- It does not independently audit external payment providers or guarantee system reliability.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance and [SECURITY.md](SECURITY.md) for reporting and safe-use requirements.

## License

[MIT](LICENSE).
