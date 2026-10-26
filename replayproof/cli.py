"""CLI with JSON and Markdown reports."""
import argparse
import json
import os
import pathlib
import sys
from .engine import ConfigurationError, execute


def markdown_report(report: dict) -> str:
    summary = report["summary"]
    lines = ["# ReplayProof Webhook Reliability Report", "", f"Generated: {report['timestamp_utc']}",
             f"Target host: `{report['target_host']}`", "",
             f"**PASS {summary['pass']} · FAIL {summary['fail']} · INCONCLUSIVE {summary['inconclusive']}**", ""]
    for case in report["cases"]:
        name = str(case["name"]).replace("`", "'").replace("\n", " ")
        lines += [f"## {name} — {case['status'].upper()}", "", f"Mode: `{case['kind']}`", ""]
        if "side_effect_delta" in case:
            lines.append(f"Observed side-effect delta: **{case['side_effect_delta']}** (max {case['max_allowed_delta']})")
        if "observed_state" in case:
            lines.append(f"Observed final state: `{json.dumps(case['observed_state'], ensure_ascii=False)}`")
        if "median_latency_ms" in case:
            lines.append(f"Median response time: {case['median_latency_ms']} ms")
        for issue in case.get("issues", []):
            lines.append(f"- FAIL: {issue.replace(chr(10), ' ')}")
        if case.get("notes"):
            lines.append(f"- NOTE: {case['notes']}")
        lines.append("")
    lines.extend(["---", "", "**Scope:** Staging test, not a security audit or proof of production correctness. "
                 "Tests require explicit observable side-effect or state assertions. Never aim at production or third-party systems.", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test webhook side-effect reliability in staging environments")
    parser.add_argument("manifest", help="JSON case manifest")
    parser.add_argument("--out", default="report", help="Output prefix (default: report)")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--stripe-secret-env", help="Env variable containing a STAGING signing secret")
    parser.add_argument("--allow-remote", action="store_true", help="Enable non-local HTTPS staging targets")
    parser.add_argument("--i-own-this-staging-endpoint", action="store_true", help="Confirm authorization to test staging target")
    args = parser.parse_args(argv)
    try:
        config = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf8"))
        secret = os.environ.get(args.stripe_secret_env) if args.stripe_secret_env else None
        if args.stripe_secret_env and not secret:
            raise ConfigurationError(f"Secret environment variable {args.stripe_secret_env} is not set")
        report = execute(config, allow_remote=args.allow_remote,
                         attested=args.i_own_this_staging_endpoint,
                         timeout=args.timeout, secret=secret)
        prefix = pathlib.Path(args.out)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        prefix.with_suffix(".json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf8")
        prefix.with_suffix(".md").write_text(markdown_report(report), encoding="utf8")
        stats = report["summary"]
        print(f"PASS {stats['pass']} | FAIL {stats['fail']} | INCONCLUSIVE {stats['inconclusive']}")
        print(f"Saved {prefix.with_suffix('.json')} and {prefix.with_suffix('.md')}")
        return 1 if stats["fail"] else (3 if stats["inconclusive"] else 0)
    except (ValueError, OSError, ConfigurationError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
