"""Dependency-free, safety-limited webhook replay test engine."""
from __future__ import annotations

import concurrent.futures
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import socket
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class ConfigurationError(ValueError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)
MAX_REQUESTS = 50


def _url_host(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ConfigurationError("Only HTTP(S) URLs with a hostname are supported")
    if parsed.username or parsed.password or parsed.fragment:
        raise ConfigurationError("URLs must not contain credentials or fragments")
    return parsed.hostname.lower()


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_destinations(config: dict, allow_remote: bool, attested: bool) -> None:
    """Fail closed unless localhost, or explicitly attested HTTPS staging host."""
    main_url = config.get("target", "")
    host = _url_host(main_url)
    urls = [main_url] + [config[k] for k in ("probe", "reset") if config.get(k)]
    for url in urls:
        other = _url_host(url)
        if other != host:
            raise ConfigurationError("Target, probe, reset must use the same hostname")
        if not _is_loopback(host) and urllib.parse.urlsplit(url).scheme != "https":
            raise ConfigurationError("Remote targets must use HTTPS")
    if _is_loopback(host):
        return
    if not allow_remote or not attested:
        raise ConfigurationError(
            "Remote testing is disabled by default. Use both --allow-remote and "
            "--i-own-this-staging-endpoint only on an environment you control."
        )
    # Do not allow explicit private/link-local/multicast/metadata addresses or hostnames
    # that currently resolve to those addresses. This is CLI-level protection, not an
    # adversarially secure network boundary against DNS rebinding; deploy only in trusted CI.
    try:
        addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ConfigurationError(f"Cannot resolve remote hostname: {exc}") from exc
    for entry in addresses:
        addr = ipaddress.ip_address(entry[4][0])
        if not addr.is_global:
            raise ConfigurationError("Remote hostname resolves to a non-public address")


def _post(url: str, event: dict | None, timeout: float, secret: str | None) -> dict:
    raw = json.dumps(event or {}, separators=(",", ":"), ensure_ascii=False).encode("utf8")
    headers = {"Content-Type": "application/json", "User-Agent": "ReplayProof/0.1"}
    if secret and event is not None:
        ts = str(int(time.time()))
        sig = hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
        headers["Stripe-Signature"] = f"t={ts},v1={sig}"
    request = urllib.request.Request(url, data=raw, headers=headers, method="POST")
    start = time.monotonic()
    try:
        with OPENER.open(request, timeout=timeout) as response:
            status = response.status
            response.read(1024)
    except urllib.error.HTTPError as exc:
        status = exc.code
        exc.close()
    except Exception as exc:
        return {"status": None, "latency_ms": round((time.monotonic() - start) * 1000, 1),
                "error": f"{type(exc).__name__}: {str(exc)[:150]}"}
    return {"status": status, "latency_ms": round((time.monotonic() - start) * 1000, 1)}


def _get_json(url: str, timeout: float) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "ReplayProof/0.1"})
    with OPENER.open(request, timeout=timeout) as response:
        data = response.read(8192)
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Probe response must be a JSON object")
    return value


def _nested(value: dict, field: str) -> Any:
    current: Any = value
    for part in field.split("."):
        if not isinstance(current, dict) or part not in current:
            raise ValueError(f"Probe field '{field}' is missing")
        current = current[part]
    return current


def validate_manifest(config: dict) -> None:
    if not isinstance(config, dict):
        raise ConfigurationError("Manifest must be a JSON object")
    if not isinstance(config.get("target"), str):
        raise ConfigurationError("Manifest needs a target URL")
    cases = config.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ConfigurationError("Manifest needs at least one case")
    total_requests = 0
    for i, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ConfigurationError(f"cases[{i}] must be an object")
        kind = case.get("kind")
        if kind not in ("duplicate", "parallel-duplicate", "retry", "reorder"):
            raise ConfigurationError(f"Invalid case kind: {kind}")
        if kind == "reorder":
            events = case.get("events")
            if not isinstance(events, list) or len(events) < 2 or len(events) > 10:
                raise ConfigurationError("reorder needs 2–10 events")
            if not all(isinstance(ev, dict) for ev in events):
                raise ConfigurationError("Each event must be an object")
            total_requests += len(events)
        else:
            if not isinstance(case.get("event"), dict):
                raise ConfigurationError(f"{kind} needs an event object")
            repeat = case.get("repeat", 2)
            if type(repeat) is not int or not 2 <= repeat <= 10:
                raise ConfigurationError("repeat must be an integer from 2 to 10")
            total_requests += repeat
        if "max_side_effect_delta" in case:
            if not isinstance(config.get("probe"), str):
                raise ConfigurationError("side-effect assertion requires probe URL")
            if type(case["max_side_effect_delta"]) is not int or case["max_side_effect_delta"] < 0:
                raise ConfigurationError("max_side_effect_delta must be a nonnegative integer")
        if "expected_state" in case and not isinstance(case["expected_state"], dict):
            raise ConfigurationError("expected_state must be a JSON object")
        if ("expected_state" in case) and not config.get("probe"):
            raise ConfigurationError("expected_state assertion requires a probe")
    if total_requests > MAX_REQUESTS:
        raise ConfigurationError(f"Manifest would send {total_requests} requests, max {MAX_REQUESTS}")


def execute(config: dict, *, allow_remote: bool = False, attested: bool = False,
            timeout: float = 3.0, secret: str | None = None) -> dict:
    validate_manifest(config)
    check_destinations(config, allow_remote, attested)
    if not 0 < timeout <= 10:
        raise ConfigurationError("Timeout must be greater than 0 and at most 10 seconds")
    result = {"tool": "ReplayProof", "version": "0.1.0", "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
              "target_host": _url_host(config["target"]), "cases": [], "summary": {}}
    for index, case in enumerate(config["cases"]):
        kind = case["kind"]
        name = case.get("name", f"case-{index+1}")
        evidence: dict[str, Any] = {"name": name, "kind": kind, "status": "inconclusive", "issues": [], "responses": []}
        try:
            if config.get("reset"):
                reset = _post(config["reset"], None, timeout, None)
                if reset.get("status") not in (200, 204):
                    raise RuntimeError(f"Reset endpoint returned {reset.get('status')}")
            before = _get_json(config["probe"], timeout) if config.get("probe") else None
            events = case["events"] if kind == "reorder" else [case["event"]] * case.get("repeat", 2)
            if kind == "parallel-duplicate":
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(events), 8)) as pool:
                    responses = list(pool.map(lambda event: _post(config["target"], event, timeout, secret), events))
            else:
                responses = [_post(config["target"], event, timeout, secret) for event in events]
            evidence["responses"] = responses
            statuses = [r.get("status") for r in responses]
            latency = [r["latency_ms"] for r in responses]
            evidence["max_latency_ms"] = max(latency)
            if len(latency) >= 2:
                evidence["median_latency_ms"] = round(statistics.median(latency), 1)
            after = _get_json(config["probe"], timeout) if config.get("probe") else None
            issues: list[str] = []
            assertions = 0
            if any(s is None or s >= 400 or s < 200 for s in statuses):
                if kind != "retry":
                    issues.append("One or more deliveries failed (non-2xx or transport error)")
                elif statuses[-1] is None or not (200 <= statuses[-1] < 300):
                    issues.append("Retry never recovered to a successful 2xx delivery")
            if kind == "retry" and statuses[0] is not None and 200 <= statuses[0] < 300:
                evidence["notes"] = "First attempt succeeded; no actual failure was simulated. The repeat still tests idempotency."
            if "max_side_effect_delta" in case:
                field = case.get("side_effect_field", "side_effects")
                start, finish = _nested(before, field), _nested(after, field)
                if not isinstance(start, (int, float)) or not isinstance(finish, (int, float)):
                    raise ValueError("side effect field must be numeric")
                delta = finish - start
                evidence["side_effect_delta"] = delta
                evidence["max_allowed_delta"] = case["max_side_effect_delta"]
                assertions += 1
                if delta < 0 or delta > case["max_side_effect_delta"]:
                    issues.append(f"Side effect delta {delta} exceeds allowed 0..{case['max_side_effect_delta']}")
            if "expected_state" in case:
                assertions += 1
                observed = {}
                for field, expected in case["expected_state"].items():
                    actual = _nested(after, field)
                    observed[field] = actual
                    if actual != expected:
                        issues.append(f"State '{field}' was {actual!r}, expected {expected!r}")
                evidence["observed_state"] = observed
            evidence["issues"] = issues
            evidence["status"] = "fail" if issues else ("pass" if assertions else "inconclusive")
            if not assertions:
                evidence["notes"] = "HTTP success alone cannot prove idempotency; add a probe/assertion."
        except Exception as exc:
            evidence["status"] = "fail"
            evidence["issues"] = [f"Test execution error: {type(exc).__name__}: {str(exc)[:200]}"]
        result["cases"].append(evidence)
    counts = {k: sum(c["status"] == k for c in result["cases"]) for k in ("pass", "fail", "inconclusive")}
    result["summary"] = counts
    result["summary"]["total"] = len(result["cases"])
    return result
