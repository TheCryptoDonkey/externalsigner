#!/usr/bin/env python3
"""Run and verify the External Signer single-worker staging acceptance gate."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.cookiejar
import itertools
import json
import os
import re
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ZERO_HASH = "0" * 64
REQUIRED_DRILLS = {
    "relay_outage",
    "dns_failure",
    "tls_failure",
    "process_restart_pending",
    "process_restart_auth_required",
    "process_restart_complete",
    "database_restore",
    "rollback",
}
FAILURE_DRILLS = {"relay_outage", "dns_failure", "tls_failure"}
SENSITIVE_TEXT = re.compile(
    r"(nsec1|nostrconnect://|bunker://|secret\s*=|password|cookie|authorization|bearer\s+)",
    re.IGNORECASE,
)
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(RuntimeError):
    """Raised when evidence is incomplete, invalid or unsafe to record."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("Evidence timestamp is invalid.") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("Evidence timestamps must include a timezone.")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def event_hash(event: dict[str, Any]) -> str:
    unsigned = {key: value for key, value in event.items() if key != "sha256"}
    return hashlib.sha256(canonical_json(unsigned)).hexdigest()


def ensure_safe_text(value: str, field: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise EvidenceError(f"{field} must not be blank.")
    if SENSITIVE_TEXT.search(cleaned):
        raise EvidenceError(f"{field} appears to contain secret material.")
    return cleaned


def validate_base_url(value: str, *, allow_http: bool = False) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if parsed.scheme not in allowed_schemes:
        raise EvidenceError("Staging base URL must use HTTPS.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise EvidenceError("Staging base URL must have a host and no credentials.")
    if parsed.query or parsed.fragment:
        raise EvidenceError("Staging base URL must not contain a query or fragment.")
    if parsed.path not in {"", "/"}:
        raise EvidenceError("Staging base URL must not contain a path.")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def validate_relay(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme != "wss" or not parsed.hostname:
        raise EvidenceError("Recorded staging relays must use wss:// and include a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise EvidenceError("Recorded relay URLs must not contain credentials or capabilities.")
    return urllib.parse.urlunsplit(("wss", parsed.netloc, parsed.path, "", ""))


def load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"Invalid JSON on evidence line {line_number}.") from exc
        if not isinstance(event, dict):
            raise EvidenceError(f"Evidence line {line_number} is not an object.")
        events.append(event)
    return events


def verify_chain(events: list[dict[str, Any]]) -> None:
    previous = ZERO_HASH
    previous_timestamp: datetime | None = None
    for index, event in enumerate(events, 1):
        if event.get("sequence") != index:
            raise EvidenceError(f"Evidence sequence is invalid at event {index}.")
        if event.get("previous_sha256") != previous:
            raise EvidenceError(f"Evidence hash chain is broken at event {index}.")
        digest = event_hash(event)
        if event.get("sha256") != digest:
            raise EvidenceError(f"Evidence event {index} has been modified.")
        timestamp = parse_timestamp(str(event.get("timestamp", "")))
        if previous_timestamp is not None and timestamp < previous_timestamp:
            raise EvidenceError(f"Evidence timestamps move backwards at event {index}.")
        previous_timestamp = timestamp
        previous = digest


def append_event(
    path: Path,
    event_type: str,
    data: dict[str, Any],
    *,
    timestamp: str | None = None,
) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as evidence:
        fcntl.flock(evidence.fileno(), fcntl.LOCK_EX)
        evidence.seek(0)
        events = []
        for line_number, line in enumerate(evidence, 1):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise EvidenceError(f"Invalid JSON on evidence line {line_number}.") from exc
        verify_chain(events)
        previous = events[-1]["sha256"] if events else ZERO_HASH
        event_timestamp = timestamp or utc_now()
        parsed_timestamp = parse_timestamp(event_timestamp)
        if events and parsed_timestamp < parse_timestamp(events[-1]["timestamp"]):
            raise EvidenceError("New evidence timestamp cannot move backwards.")
        event = {
            "sequence": len(events) + 1,
            "timestamp": event_timestamp,
            "type": event_type,
            "data": data,
            "previous_sha256": previous,
        }
        event["sha256"] = event_hash(event)
        evidence.seek(0, os.SEEK_END)
        evidence.write(json.dumps(event, sort_keys=True) + "\n")
        evidence.flush()
        os.fsync(evidence.fileno())
        fcntl.flock(evidence.fileno(), fcntl.LOCK_UN)
    return event


def initial_data(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events or events[0].get("type") != "initialised":
        raise EvidenceError("Evidence must start with an initialised event.")
    data = events[0].get("data")
    if not isinstance(data, dict):
        raise EvidenceError("Initial evidence data must be an object.")
    return data


def cookie_opener(cookie_path: Path) -> urllib.request.OpenerDirector:
    if not cookie_path.is_file():
        raise EvidenceError("The cookie jar does not exist.")
    jar = http.cookiejar.MozillaCookieJar(str(cookie_path))
    try:
        jar.load(ignore_discard=True, ignore_expires=False)
    except (http.cookiejar.LoadError, OSError) as exc:
        raise EvidenceError("The cookie jar could not be loaded.") from exc
    context = ssl.create_default_context()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=context),
    )


def request_json(
    opener: urllib.request.OpenerDirector,
    method: str,
    url: str,
    *,
    payload: dict[str, Any] | None = None,
    timeout: float = 20,
) -> Any:
    body = canonical_json(payload) if payload is not None else None
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status < 200 or response.status >= 300:
                raise EvidenceError(f"Staging request returned HTTP {response.status}.")
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise EvidenceError("Staging request did not return JSON.")
            return json.load(response)
    except urllib.error.HTTPError as exc:
        raise EvidenceError(f"Staging request returned HTTP {exc.code}.") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"Staging request failed: {type(exc).__name__}.") from exc


def probe_once(
    evidence_path: Path,
    cookie_path: Path,
    *,
    timeout: float = 20,
    poll_interval: float = 1,
    expect_failure_during: str | None = None,
) -> bool:
    events = load_events(evidence_path)
    verify_chain(events)
    setup = initial_data(events)
    base_url = setup["base_url"]
    connection_name = setup["connection_name"]
    started = time.monotonic()
    authenticated_connection_found = False
    try:
        opener = cookie_opener(cookie_path)
        connections = request_json(
            opener,
            "GET",
            f"{base_url}/externalsigner/api/v1/connections",
            timeout=timeout,
        )
        if not isinstance(connections, list) or not all(
            isinstance(item, dict) for item in connections
        ):
            raise EvidenceError("The staging connection response has an invalid shape.")
        matches = [item for item in connections if item.get("name") == connection_name]
        if len(matches) != 1:
            raise EvidenceError("The named staging signer connection is not unique.")
        connection = matches[0]
        if not isinstance(connection.get("id"), str) or not connection["id"]:
            raise EvidenceError("The staging signer connection has no valid identifier.")
        authenticated_connection_found = True
        if connection.get("status") != "connected":
            raise EvidenceError(
                f"The staging signer connection is {connection.get('status', 'unknown')}."
            )
        operation = request_json(
            opener,
            "POST",
            f"{base_url}/externalsigner/api/v1/connections/{connection['id']}/requests",
            payload={"method": "ping", "params": []},
            timeout=timeout,
        )
        if not isinstance(operation, dict) or not isinstance(operation.get("id"), str):
            raise EvidenceError("The signer ping response has no valid operation identifier.")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = request_json(
                opener,
                "GET",
                f"{base_url}/externalsigner/api/v1/operations/{operation['id']}",
                timeout=timeout,
            )
            if not isinstance(current, dict):
                raise EvidenceError("The signer operation response has an invalid shape.")
            if current.get("status") == "complete":
                if expect_failure_during:
                    append_event(
                        evidence_path,
                        "probe",
                        {
                            "result": "unexpected_pass",
                            "expected_failure_during": expect_failure_during,
                            "connection_status": "connected",
                            "operation_status": "complete",
                            "duration_ms": round((time.monotonic() - started) * 1000),
                        },
                    )
                    return False
                append_event(
                    evidence_path,
                    "probe",
                    {
                        "result": "pass",
                        "connection_status": "connected",
                        "operation_status": "complete",
                        "duration_ms": round((time.monotonic() - started) * 1000),
                    },
                )
                return True
            if current.get("status") == "failed":
                raise EvidenceError("The signer ping reached a failed terminal state.")
            time.sleep(poll_interval)
        raise EvidenceError("The signer ping did not finish before the probe timeout.")
    except EvidenceError as exc:
        failure = str(exc)
        if SENSITIVE_TEXT.search(failure):
            failure = "Probe authentication material was unavailable or invalid."
        expectation_met = bool(expect_failure_during and authenticated_connection_found)
        result = "expected_failure" if expectation_met else "fail"
        data: dict[str, Any] = {
            "result": result,
            "failure_class": type(exc).__name__,
            "failure": failure,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
        if expectation_met:
            data["expected_failure_during"] = expect_failure_during
        append_event(
            evidence_path,
            "probe",
            data,
        )
        return expectation_met


def evaluate_evidence(events: list[dict[str, Any]]) -> dict[str, Any]:
    verify_chain(events)
    setup = initial_data(events)
    start = parse_timestamp(events[0]["timestamp"])
    end = parse_timestamp(events[-1]["timestamp"])
    elapsed_hours = (end - start).total_seconds() / 3600
    required_hours = float(setup["required_days"]) * 24
    probes = [event for event in events if event["type"] == "probe"]
    passing_probes = [event for event in probes if event["data"].get("result") == "pass"]
    expected_failure_probes = [
        event for event in probes if event["data"].get("result") == "expected_failure"
    ]
    failed_probes = [
        event for event in probes if event["data"].get("result") not in {"pass", "expected_failure"}
    ]
    reviews = [event for event in events if event["type"] == "monitoring_review"]
    failed_reviews = [event for event in reviews if event["data"].get("result") != "pass"]
    review_days = {
        parse_timestamp(event["timestamp"]).date().isoformat()
        for event in reviews
        if event["data"].get("result") == "pass"
        and SHA256_RE.fullmatch(str(event["data"].get("artifact_sha256", "")))
    }
    probe_gaps = [
        (parse_timestamp(second["timestamp"]) - parse_timestamp(first["timestamp"])).total_seconds()
        for first, second in itertools.pairwise(probes)
    ]
    coverage_gaps = probe_gaps[:]
    if probes:
        coverage_gaps.extend(
            [
                (parse_timestamp(probes[0]["timestamp"]) - start).total_seconds(),
                (end - parse_timestamp(probes[-1]["timestamp"])).total_seconds(),
            ]
        )
    max_gap = max(coverage_gaps, default=0)
    passed_drills = {
        event["data"].get("drill")
        for event in events
        if event["type"] == "drill"
        and event["data"].get("result") == "pass"
        and SHA256_RE.fullmatch(str(event["data"].get("artifact_sha256", "")))
    }
    missing_drills = sorted(REQUIRED_DRILLS - passed_drills)
    observed_failure_drills = {
        event["data"].get("expected_failure_during") for event in expected_failure_probes
    }
    missing_failure_drills = sorted(FAILURE_DRILLS - observed_failure_drills)
    failures = []
    if setup.get("workers") != 1:
        failures.append("The staging instance was not recorded as one worker.")
    if not str(setup.get("base_url", "")).startswith("https://"):
        failures.append("The staging instance did not use HTTPS.")
    if elapsed_hours < required_hours:
        failures.append(f"Only {elapsed_hours:.2f} of {required_hours:.2f} required hours elapsed.")
    if len(passing_probes) < 2:
        failures.append("At least two successful authenticated signer probes are required.")
    if failed_probes:
        failures.append(f"{len(failed_probes)} signer probe(s) failed.")
    if len(review_days) < 7:
        failures.append("Passing monitoring reviews are required on seven UTC dates.")
    if failed_reviews:
        failures.append(f"{len(failed_reviews)} monitoring review(s) failed.")
    if max_gap > int(setup["maximum_probe_gap_seconds"]):
        failures.append(f"The largest probe gap was {max_gap:.0f} seconds.")
    if missing_drills:
        failures.append("Missing passing drills: " + ", ".join(missing_drills) + ".")
    if missing_failure_drills:
        failures.append(
            "Missing observed network failures: " + ", ".join(missing_failure_drills) + "."
        )
    return {
        "candidate_commit": setup["candidate_commit"],
        "lnbits_version": setup["lnbits_version"],
        "database_engine": setup["database_engine"],
        "elapsed_hours": round(elapsed_hours, 2),
        "probe_count": len(probes),
        "failed_probe_count": len(failed_probes),
        "expected_failure_probe_count": len(expected_failure_probes),
        "monitoring_review_days": sorted(review_days),
        "failed_monitoring_review_count": len(failed_reviews),
        "maximum_probe_gap_seconds": round(max_gap),
        "passed_drills": sorted(item for item in passed_drills if item),
        "missing_drills": missing_drills,
        "missing_observed_failure_drills": missing_failure_drills,
        "eligible": not failures,
        "failures": failures,
        "final_evidence_sha256": events[-1]["sha256"],
    }


def command_init(args: argparse.Namespace) -> int:
    path = Path(args.evidence)
    if load_events(path):
        raise EvidenceError("Evidence already exists; refusing to replace it.")
    if not COMMIT_RE.fullmatch(args.candidate_commit):
        raise EvidenceError("Candidate commit must be a full 40-character Git SHA.")
    if args.workers != 1:
        raise EvidenceError("This release candidate supports exactly one LNbits worker.")
    if args.required_days < 7:
        raise EvidenceError("The production gate requires at least seven elapsed days.")
    if not 1 <= args.maximum_probe_gap_seconds <= 900:
        raise EvidenceError("The maximum signer-probe gap must be between 1 and 900 seconds.")
    relays = [validate_relay(value) for value in args.relay]
    data = {
        "candidate_commit": args.candidate_commit,
        "lnbits_version": ensure_safe_text(args.lnbits_version, "LNbits version"),
        "database_engine": args.database_engine,
        "base_url": validate_base_url(args.base_url, allow_http=args.allow_http),
        "connection_name": ensure_safe_text(args.connection_name, "connection name"),
        "relays": relays,
        "workers": args.workers,
        "required_days": args.required_days,
        "maximum_probe_gap_seconds": args.maximum_probe_gap_seconds,
        "operator": ensure_safe_text(args.operator, "operator"),
    }
    event = append_event(path, "initialised", data)
    print(json.dumps({"evidence": str(path), "sha256": event["sha256"]}, indent=2))
    return 0


def command_probe(args: argparse.Namespace) -> int:
    if args.timeout <= 0 or args.poll_interval <= 0:
        raise EvidenceError("Probe timeout and poll interval must be positive.")
    passed = probe_once(
        Path(args.evidence),
        Path(args.cookie_jar),
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        expect_failure_during=args.expect_failure_during,
    )
    if args.expect_failure_during:
        message = (
            "Expected signer failure observed." if passed else "Signer unexpectedly responded."
        )
    else:
        message = "Signer probe passed." if passed else "Signer probe failed."
    print(message)
    return 0 if passed else 1


def command_run(args: argparse.Namespace) -> int:
    events = load_events(Path(args.evidence))
    verify_chain(events)
    maximum_gap = int(initial_data(events)["maximum_probe_gap_seconds"])
    if not 0 < args.interval_seconds <= maximum_gap:
        raise EvidenceError(
            "Probe interval must be positive and no greater than the recorded maximum gap."
        )
    if args.duration_seconds is not None and args.duration_seconds <= 0:
        raise EvidenceError("Run duration must be positive when supplied.")
    if args.timeout <= 0 or args.poll_interval <= 0:
        raise EvidenceError("Probe timeout and poll interval must be positive.")
    stopped = False

    def stop(_signum: int, _frame: Any) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    deadline = time.monotonic() + args.duration_seconds if args.duration_seconds else None
    failures = 0
    while not stopped and (deadline is None or time.monotonic() < deadline):
        if not probe_once(
            Path(args.evidence),
            Path(args.cookie_jar),
            timeout=args.timeout,
            poll_interval=args.poll_interval,
        ):
            failures += 1
        sleep_until = time.monotonic() + args.interval_seconds
        while not stopped and time.monotonic() < sleep_until:
            time.sleep(min(1, sleep_until - time.monotonic()))
    append_event(
        Path(args.evidence),
        "controller_stopped",
        {"probe_failures_during_run": failures, "signal_received": stopped},
    )
    return 0 if failures == 0 else 1


def command_drill(args: argparse.Namespace) -> int:
    events = load_events(Path(args.evidence))
    verify_chain(events)
    initial_data(events)
    note = ensure_safe_text(args.note, "drill note")
    data: dict[str, Any] = {"drill": args.drill, "result": args.result, "note": note}
    if args.result == "pass" and not args.artifact_sha256:
        raise EvidenceError("A passing drill requires a sanitised artifact SHA-256.")
    if args.artifact_sha256:
        if not SHA256_RE.fullmatch(args.artifact_sha256):
            raise EvidenceError("Artifact SHA-256 must be 64 lowercase hex characters.")
        data["artifact_sha256"] = args.artifact_sha256
    event = append_event(Path(args.evidence), "drill", data)
    print(json.dumps({"drill": args.drill, "sha256": event["sha256"]}, indent=2))
    return 0


def command_review(args: argparse.Namespace) -> int:
    events = load_events(Path(args.evidence))
    verify_chain(events)
    initial_data(events)
    note = ensure_safe_text(args.note, "monitoring review note")
    data: dict[str, Any] = {"result": args.result, "note": note}
    if args.result == "pass" and not args.artifact_sha256:
        raise EvidenceError("A passing monitoring review requires an artifact SHA-256.")
    if args.artifact_sha256:
        if not SHA256_RE.fullmatch(args.artifact_sha256):
            raise EvidenceError("Artifact SHA-256 must be 64 lowercase hex characters.")
        data["artifact_sha256"] = args.artifact_sha256
    event = append_event(Path(args.evidence), "monitoring_review", data)
    print(json.dumps({"monitoring_review": args.result, "sha256": event["sha256"]}, indent=2))
    return 0


def command_verify(args: argparse.Namespace) -> int:
    summary = evaluate_evidence(load_events(Path(args.evidence)))
    print(json.dumps(summary, indent=2))
    return 0 if summary["eligible"] else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    subparsers = root.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="Start a new append-only soak record.")
    init.add_argument("--evidence", required=True)
    init.add_argument("--candidate-commit", required=True)
    init.add_argument("--lnbits-version", required=True)
    init.add_argument("--database-engine", choices=["sqlite", "postgresql"], required=True)
    init.add_argument("--base-url", required=True)
    init.add_argument("--connection-name", required=True)
    init.add_argument("--relay", action="append", required=True)
    init.add_argument("--operator", required=True)
    init.add_argument("--workers", type=int, default=1)
    init.add_argument("--required-days", type=float, default=7)
    init.add_argument("--maximum-probe-gap-seconds", type=int, default=900)
    init.add_argument("--allow-http", action="store_true", help=argparse.SUPPRESS)
    init.set_defaults(func=command_init)

    probe = subparsers.add_parser("probe", help="Perform one authenticated signer ping.")
    probe.add_argument("--evidence", required=True)
    probe.add_argument("--cookie-jar", required=True)
    probe.add_argument("--timeout", type=float, default=20)
    probe.add_argument("--poll-interval", type=float, default=1)
    probe.add_argument("--expect-failure-during", choices=sorted(FAILURE_DRILLS))
    probe.set_defaults(func=command_probe)

    run = subparsers.add_parser("run", help="Run probes until stopped or duration elapses.")
    run.add_argument("--evidence", required=True)
    run.add_argument("--cookie-jar", required=True)
    run.add_argument("--interval-seconds", type=float, default=300)
    run.add_argument("--duration-seconds", type=float)
    run.add_argument("--timeout", type=float, default=20)
    run.add_argument("--poll-interval", type=float, default=1)
    run.set_defaults(func=command_run)

    drill = subparsers.add_parser("drill", help="Record one observed staging drill.")
    drill.add_argument("--evidence", required=True)
    drill.add_argument("--drill", choices=sorted(REQUIRED_DRILLS), required=True)
    drill.add_argument("--result", choices=["pass", "fail"], required=True)
    drill.add_argument("--note", required=True)
    drill.add_argument("--artifact-sha256")
    drill.set_defaults(func=command_drill)

    review = subparsers.add_parser("review", help="Record a manual monitoring review.")
    review.add_argument("--evidence", required=True)
    review.add_argument("--result", choices=["pass", "fail"], required=True)
    review.add_argument("--note", required=True)
    review.add_argument("--artifact-sha256")
    review.set_defaults(func=command_review)

    verify = subparsers.add_parser("verify", help="Verify the complete elapsed-time gate.")
    verify.add_argument("--evidence", required=True)
    verify.set_defaults(func=command_verify)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.func(args))
    except EvidenceError as exc:
        print(f"staging acceptance error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
