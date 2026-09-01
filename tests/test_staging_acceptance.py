from __future__ import annotations

import argparse
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType

import pytest


def load_staging_module() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "staging_acceptance.py"
    spec = importlib.util.spec_from_file_location("staging_acceptance", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


staging = load_staging_module()


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def initial_setup(**overrides: object) -> dict[str, object]:
    setup: dict[str, object] = {
        "candidate_commit": "a" * 40,
        "lnbits_version": "1.5.6",
        "database_engine": "postgresql",
        "base_url": "https://staging.example.com",
        "connection_name": "release-candidate",
        "relays": ["wss://relay.example.com"],
        "workers": 1,
        "required_days": 7,
        "maximum_probe_gap_seconds": 604_800,
        "operator": "TheCryptoDonkey",
    }
    setup.update(overrides)
    return setup


def init_args(path: Path, **overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "evidence": str(path),
        "candidate_commit": "a" * 40,
        "lnbits_version": "1.5.6",
        "database_engine": "postgresql",
        "base_url": "https://staging.example.com",
        "connection_name": "release-candidate",
        "relay": ["wss://relay.example.com"],
        "operator": "TheCryptoDonkey",
        "workers": 1,
        "required_days": 7,
        "maximum_probe_gap_seconds": 900,
        "allow_http": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_complete_elapsed_evidence_is_eligible(tmp_path: Path) -> None:
    evidence = tmp_path / "soak.jsonl"
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    staging.append_event(evidence, "initialised", initial_setup(), timestamp=timestamp(start))
    staging.append_event(
        evidence,
        "probe",
        {"result": "pass"},
        timestamp=timestamp(start + timedelta(minutes=1)),
    )
    for index, drill in enumerate(sorted(staging.REQUIRED_DRILLS), 1):
        if drill in staging.FAILURE_DRILLS:
            staging.append_event(
                evidence,
                "probe",
                {"result": "expected_failure", "expected_failure_during": drill},
                timestamp=timestamp(start + timedelta(hours=index, minutes=-30)),
            )
        staging.append_event(
            evidence,
            "drill",
            {
                "drill": drill,
                "result": "pass",
                "note": f"Observed drill {index}.",
                "artifact_sha256": "b" * 64,
            },
            timestamp=timestamp(start + timedelta(hours=index)),
        )
    for day in range(7):
        staging.append_event(
            evidence,
            "monitoring_review",
            {
                "result": "pass",
                "note": f"Reviewed UTC day {day + 1}.",
                "artifact_sha256": "c" * 64,
            },
            timestamp=timestamp(start + timedelta(days=day, hours=12)),
        )
    staging.append_event(
        evidence,
        "probe",
        {"result": "pass"},
        timestamp=timestamp(start + timedelta(days=7)),
    )

    summary = staging.evaluate_evidence(staging.load_events(evidence))

    assert summary["eligible"] is True
    assert summary["elapsed_hours"] == 168
    assert summary["probe_count"] == 5
    assert summary["failed_probe_count"] == 0
    assert summary["expected_failure_probe_count"] == 3
    assert len(summary["monitoring_review_days"]) == 7
    assert summary["missing_drills"] == []
    assert summary["missing_observed_failure_drills"] == []
    assert len(summary["final_evidence_sha256"]) == 64


def test_incomplete_or_failed_evidence_is_not_eligible(tmp_path: Path) -> None:
    evidence = tmp_path / "soak.jsonl"
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    staging.append_event(evidence, "initialised", initial_setup(), timestamp=timestamp(start))
    staging.append_event(
        evidence,
        "probe",
        {"result": "fail"},
        timestamp=timestamp(start + timedelta(hours=1)),
    )

    summary = staging.evaluate_evidence(staging.load_events(evidence))

    assert summary["eligible"] is False
    assert summary["failed_probe_count"] == 1
    assert set(summary["missing_drills"]) == staging.REQUIRED_DRILLS
    assert any("required hours" in failure for failure in summary["failures"])


def test_modified_or_backdated_evidence_is_rejected(tmp_path: Path) -> None:
    evidence = tmp_path / "soak.jsonl"
    start = datetime(2026, 9, 1, tzinfo=timezone.utc)
    staging.append_event(evidence, "initialised", initial_setup(), timestamp=timestamp(start))
    with pytest.raises(staging.EvidenceError, match="move backwards"):
        staging.append_event(
            evidence,
            "probe",
            {"result": "pass"},
            timestamp=timestamp(start - timedelta(seconds=1)),
        )

    staging.append_event(
        evidence,
        "probe",
        {"result": "pass"},
        timestamp=timestamp(start + timedelta(seconds=1)),
    )

    lines = evidence.read_text().splitlines()
    evidence.write_text("\n".join(lines).replace('"result": "pass"', '"result": "fail"') + "\n")
    with pytest.raises(staging.EvidenceError, match="modified"):
        staging.verify_chain(staging.load_events(evidence))


@pytest.mark.parametrize(
    "url",
    [
        "http://staging.example.com",
        "https://user:pass@staging.example.com",
        "https://staging.example.com/private/path",
        "https://staging.example.com?capability=secret",
    ],
)
def test_staging_url_rejects_unsafe_forms(url: str) -> None:
    with pytest.raises(staging.EvidenceError):
        staging.validate_base_url(url)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"workers": 2}, "exactly one"),
        ({"required_days": 6.99}, "at least seven"),
        ({"maximum_probe_gap_seconds": 901}, "between 1 and 900"),
    ],
)
def test_initialisation_enforces_release_gate(
    tmp_path: Path, overrides: dict[str, object], message: str
) -> None:
    with pytest.raises(staging.EvidenceError, match=message):
        staging.command_init(init_args(tmp_path / "soak.jsonl", **overrides))


def test_missing_cookie_records_a_redacted_failed_probe(tmp_path: Path) -> None:
    evidence = tmp_path / "soak.jsonl"
    staging.append_event(evidence, "initialised", initial_setup())

    assert staging.probe_once(evidence, tmp_path / "missing-cookies.txt") is False

    failure = staging.load_events(evidence)[-1]
    assert failure["data"]["result"] == "fail"
    assert failure["data"]["failure"] == (
        "Probe authentication material was unavailable or invalid."
    )
    assert "missing-cookies" not in str(failure)

    assert (
        staging.probe_once(
            evidence,
            tmp_path / "missing-cookies.txt",
            expect_failure_during="relay_outage",
        )
        is False
    )
    auth_failure = staging.load_events(evidence)[-1]
    assert auth_failure["data"]["result"] == "fail"
    assert "expected_failure_during" not in auth_failure["data"]


def test_authenticated_network_failure_satisfies_expected_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "soak.jsonl"
    staging.append_event(evidence, "initialised", initial_setup())
    responses: list[object] = [
        [{"id": "connection-id", "name": "release-candidate", "status": "connected"}],
        staging.EvidenceError("The signer ping did not finish before the probe timeout."),
    ]

    monkeypatch.setattr(staging, "cookie_opener", lambda _path: object())

    def request(*_args: object, **_kwargs: object) -> object:
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(staging, "request_json", request)

    assert (
        staging.probe_once(
            evidence,
            tmp_path / "cookies.txt",
            expect_failure_during="relay_outage",
        )
        is True
    )
    event = staging.load_events(evidence)[-1]
    assert event["data"]["result"] == "expected_failure"
    assert event["data"]["expected_failure_during"] == "relay_outage"


def test_expected_failure_probe_rejects_a_signer_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "soak.jsonl"
    staging.append_event(evidence, "initialised", initial_setup())
    responses = iter(
        [
            [{"id": "connection-id", "name": "release-candidate", "status": "connected"}],
            {"id": "operation-id"},
            {"status": "complete"},
        ]
    )

    monkeypatch.setattr(staging, "cookie_opener", lambda _path: object())
    monkeypatch.setattr(staging, "request_json", lambda *_args, **_kwargs: next(responses))

    assert (
        staging.probe_once(
            evidence,
            tmp_path / "cookies.txt",
            expect_failure_during="tls_failure",
        )
        is False
    )
    event = staging.load_events(evidence)[-1]
    assert event["data"]["result"] == "unexpected_pass"
    assert event["data"]["expected_failure_during"] == "tls_failure"
