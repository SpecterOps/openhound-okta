import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import requests

from tools.oin_lab.lab import (
    LabSafetyError,
    MATRIX_PATH,
    OktaApiError,
    OktaNotFound,
    RunStore,
    load_cases,
    matrix_digest,
)
from tools.oin_lab.sweep import (
    SweepStore,
    audit_sweep_residue,
    compact_residue_audit,
    compact_sweep_report,
    select_sweep_cases,
    summarize_sweep,
)


TENANT_URL = "https://lab.okta.test"


def _selected_cases():
    return select_sweep_cases(
        load_cases(),
        ("slack-workspace", "asana-default"),
        include_discovery=True,
    )


def _store(tmp_path: Path) -> SweepStore:
    return SweepStore(tmp_path, TENANT_URL, "campaign1")


def _manifest(tmp_path: Path) -> tuple[SweepStore, dict]:
    store = _store(tmp_path)
    manifest = store.load_or_create(
        _selected_cases(),
        matrix_path=MATRIX_PATH,
        matrix_sha256=matrix_digest(MATRIX_PATH),
        include_discovery=True,
    )
    return store, manifest


def _record_clean_capture(tmp_path: Path, case: dict) -> None:
    run_store = RunStore(tmp_path, TENANT_URL, case["run_id"])
    state = run_store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case["case_id"]] = {
        "case_id": case["case_id"],
        "app_key": case["app_key"],
        "label": f"oin-lab-{case['run_id']}-{case['case_id']}",
        "app_id": "0oa-test",
        "deleted_at": "2026-08-15T00:00:00+00:00",
        "active_trace": {
            "user_create_requested_at": "2026-08-15T00:00:00+00:00",
            "user_deleted_at": "2026-08-15T00:00:01+00:00",
            "app_deleted_at": "2026-08-15T00:00:02+00:00",
        },
        "active_trace_attempt": {
            "outcome": "captured_clean",
            "cleanup_verified": True,
        },
    }
    run_store.save(state)
    run_store.write_capture(
        "active-review",
        case["case_id"],
        json.dumps(
            {
                "schema_version": 1,
                "request_url": "https://sp.example.test/saml/consume",
                "request_method": "POST",
                "saml_parameter": "SAMLResponse",
                "saml": {
                    "message_type": "Response",
                    "destinations_and_recipients": [
                        "https://sp.example.test/saml/consume"
                    ],
                    "audiences": ["https://sp.example.test/saml"],
                },
                "app_link_selection": {
                    "available_count": 2,
                    "available_labels": ["Primary", "Secondary"],
                    "selected_index": 1,
                    "selected_label": "Primary",
                },
                "requires_human_review": True,
            }
        ),
    )


def test_sweep_plan_is_immutable_and_renders_one_next_command(tmp_path: Path):
    store, manifest = _manifest(tmp_path)

    assert [case["run_id"] for case in manifest["cases"]] == [
        "campaign1-001",
        "campaign1-002",
    ]
    assert store.manifest_path.stat().st_mode & 0o777 == 0o600

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    assert report["safe_to_continue"] is True
    assert report["counts"]["pending"] == 2
    assert report["next_case"]["case_id"] == "slack-workspace"
    assert report["next_command"].count("--case") == 1
    assert "--include-discovery" not in report["next_command"]


def test_sweep_status_advances_after_clean_capture_and_marks_discovery(
    tmp_path: Path,
):
    store, manifest = _manifest(tmp_path)
    _record_clean_capture(tmp_path, manifest["cases"][0])

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    assert report["counts"]["captured_clean"] == 1
    assert report["next_case"]["case_id"] == "asana-default"
    assert "--include-discovery" in report["next_command"]
    assert report["results"][0]["evidence"]["audiences"] == [
        "https://sp.example.test/saml"
    ]
    assert report["results"][0]["evidence"]["app_link_selection"] == {
        "available_count": 2,
        "available_labels": ["Primary", "Secondary"],
        "selected_index": 1,
        "selected_label": "Primary",
    }
    compact = compact_sweep_report(report)
    assert "results" not in compact
    assert compact["last_attempted"]["status"] == "captured_clean"
    assert compact["blocking_results"] == []


def test_sweep_status_stops_when_user_cleanup_is_unverified(tmp_path: Path):
    store, manifest = _manifest(tmp_path)
    case = manifest["cases"][0]
    run_store = RunStore(tmp_path, TENANT_URL, case["run_id"])
    state = run_store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case["case_id"]] = {
        "case_id": case["case_id"],
        "app_key": case["app_key"],
        "label": f"oin-lab-{case['run_id']}-{case['case_id']}",
        "app_id": "0oa-test",
        "deleted_at": "2026-08-15T00:00:00+00:00",
        "active_trace": {
            "user_create_requested_at": "2026-08-15T00:00:00+00:00",
            "user_id": "00u-test",
        },
    }
    run_store.save(state)

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
        now=datetime.now(UTC) + timedelta(minutes=11),
    )

    assert report["safe_to_continue"] is False
    assert report["operator_action"] == "stop_cleanup_or_review_unverified"
    assert report["next_command"] is None
    assert report["results"][0]["status"] == "cleanup_unverified"
    assert report["results"][0]["reason"] == ("ephemeral user cleanup is unverified")


def test_sweep_status_waits_while_active_trace_command_is_still_running(
    tmp_path: Path,
):
    store, manifest = _manifest(tmp_path)
    case = manifest["cases"][0]
    run_store = RunStore(tmp_path, TENANT_URL, case["run_id"])
    state = run_store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case["case_id"]] = {
        "case_id": case["case_id"],
        "app_key": case["app_key"],
        "label": f"oin-lab-{case['run_id']}-{case['case_id']}",
        "app_id": "0oa-test",
        "active_trace": {
            "started_at": "2026-08-17T00:00:00+00:00",
            "user_create_requested_at": "2026-08-17T00:00:01+00:00",
            "user_id": "00u-test",
        },
    }
    run_store.save(state)

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    assert report["safe_to_continue"] is True
    assert report["operator_action"] == "wait_for_current_case"
    assert report["counts"]["case_running"] == 1
    assert report["counts"]["cleanup_unverified"] == 0
    assert report["current_case"]["case_id"] == case["case_id"]
    assert report["next_case"] is None
    assert report["next_command"] is None
    assert report["all_cases_attempted"] is False


def test_sweep_status_stops_when_attempt_marks_cleanup_incomplete(tmp_path: Path):
    store, manifest = _manifest(tmp_path)
    case = manifest["cases"][0]
    run_store = RunStore(tmp_path, TENANT_URL, case["run_id"])
    state = run_store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case["case_id"]] = {
        "case_id": case["case_id"],
        "app_key": case["app_key"],
        "label": f"oin-lab-{case['run_id']}-{case['case_id']}",
        "app_id": "0oa-test",
        "deleted_at": "2026-08-15T00:00:00+00:00",
        "active_trace_attempt": {
            "outcome": "cleanup_incomplete",
            "cleanup_verified": False,
            "failure_category": "outbound_saml_response_missing",
            "failure_scope": "case",
        },
    }
    run_store.save(state)

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    assert report["safe_to_continue"] is False
    assert report["counts"]["cleanup_unverified"] == 1
    assert report["results"][0]["reason"] == "cleanup attempt remains unverified"


def test_sweep_status_stops_on_a_clean_campaign_scoped_failure(tmp_path: Path):
    store, manifest = _manifest(tmp_path)
    case = manifest["cases"][0]
    run_store = RunStore(tmp_path, TENANT_URL, case["run_id"])
    state = run_store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case["case_id"]] = {
        "case_id": case["case_id"],
        "app_key": case["app_key"],
        "label": f"oin-lab-{case['run_id']}-{case['case_id']}",
        "app_id": "0oa-test",
        "deleted_at": "2026-08-15T00:00:00+00:00",
        "active_trace_attempt": {
            "outcome": "failed_clean",
            "cleanup_verified": True,
            "failure_category": "okta_transport",
            "failure_scope": "campaign",
        },
    }
    run_store.save(state)

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    assert report["safe_to_continue"] is False
    assert report["operator_action"] == "stop_campaign_failure"
    assert report["next_command"] is None
    assert report["counts"]["campaign_failure"] == 1
    assert report["results"][0]["status"] == "campaign_failure"


def test_sweep_status_reclassifies_legacy_catalog_403_as_case_scoped(
    tmp_path: Path,
):
    store, manifest = _manifest(tmp_path)
    case = manifest["cases"][0]
    run_store = RunStore(tmp_path, TENANT_URL, case["run_id"])
    state = run_store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case["case_id"]] = {
        "case_id": case["case_id"],
        "app_key": case["app_key"],
        "label": f"oin-lab-{case['run_id']}-{case['case_id']}",
        "app_id": "0oa-test",
        "deleted_at": "2026-08-15T00:00:00+00:00",
        "active_trace_attempt": {
            "outcome": "failed_clean",
            "cleanup_verified": True,
            "failure_type": "OktaApiError",
            "failure_category": "okta_authorization",
            "failure_scope": "campaign",
            "okta_status_code": 403,
        },
    }
    run_store.save(state)

    report = summarize_sweep(
        store,
        current_matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    result = report["results"][0]
    assert report["safe_to_continue"] is True
    assert report["operator_action"] == "run_exactly_one_next_command"
    assert result["status"] == "attempted_clean_no_capture"
    assert result["attempt"]["failure_category"] == "catalog_request_rejected"
    assert result["attempt"]["failure_scope"] == "case"
    assert result["attempt"]["classification_reconciled_from_legacy"] is True


def test_full_sweep_selection_excludes_only_blocked_cases():
    selected = select_sweep_cases(load_cases(), (), include_discovery=True)

    assert selected
    assert all(case.readiness != "blocked" for case in selected)
    assert {case.readiness for case in selected} == {"ready", "discovery"}
    assert {case.case_id for case in selected}.isdisjoint(
        {"okta-org2org-explicit", "scim2-test-app"}
    )


class _AuditClient:
    def __init__(self, *, app_residue: bool = False, user_residue: bool = False):
        self.app_residue = app_residue
        self.user_residue = user_residue

    def find_applications_by_label(self, label: str) -> list[dict]:
        return [{"label": label}] if self.app_residue else []

    def get_user(self, login: str) -> dict:
        if self.user_residue:
            return {"profile": {"login": login}}
        response = requests.Response()
        response.status_code = 404
        response._content = b'{"errorCode":"E0000007"}'
        raise OktaNotFound("GET", "/api/v1/users/{login}", response)


def test_sweep_residue_audit_is_exact_and_read_only(tmp_path: Path):
    store, _ = _manifest(tmp_path)

    clean = audit_sweep_residue(_AuditClient(), store)  # type: ignore[arg-type]
    residue = audit_sweep_residue(
        _AuditClient(app_residue=True, user_residue=True),  # type: ignore[arg-type]
        store,
    )

    assert clean["read_only"] is True
    assert clean["clean"] is True
    assert clean["application_residue_count"] == 0
    assert clean["user_residue_count"] == 0
    assert residue["clean"] is False
    assert residue["application_residue_count"] == 2
    assert residue["user_residue_count"] == 2
    assert compact_residue_audit(clean)["residue_results"] == []
    assert len(compact_residue_audit(residue)["residue_results"]) == 2


class _RateLimitedAuditClient(_AuditClient):
    def __init__(self, *, rate_limit_attempts: int = 1):
        super().__init__()
        self.application_attempts = 0
        self.rate_limit_attempts = rate_limit_attempts

    def find_applications_by_label(self, label: str) -> list[dict]:
        self.application_attempts += 1
        if self.application_attempts <= self.rate_limit_attempts:
            response = requests.Response()
            response.status_code = 429
            response.headers["X-Rate-Limit-Reset"] = "105"
            response._content = b'{"errorCode":"E0000047"}'
            raise OktaApiError("GET", "/api/v1/apps", response)
        return []


def test_sweep_residue_audit_retries_rate_limit_at_exact_read(tmp_path: Path):
    store, _ = _manifest(tmp_path)
    client = _RateLimitedAuditClient()
    delays: list[float] = []

    audit = audit_sweep_residue(
        client,  # type: ignore[arg-type]
        store,
        max_attempts=2,
        sleep=delays.append,
        clock=lambda: 100.0,
    )

    assert audit["clean"] is True
    assert client.application_attempts == 3
    assert delays == [5.25]


def test_sweep_residue_audit_stops_after_bounded_rate_limit_retries(
    tmp_path: Path,
):
    store, _ = _manifest(tmp_path)
    client = _RateLimitedAuditClient(rate_limit_attempts=2)
    delays: list[float] = []

    with pytest.raises(OktaApiError, match="returned 429"):
        audit_sweep_residue(
            client,  # type: ignore[arg-type]
            store,
            max_attempts=2,
            sleep=delays.append,
            clock=lambda: 100.0,
        )

    assert client.application_attempts == 2
    assert delays == [5.25]


def test_sweep_residue_audit_rejects_unbounded_attempts(tmp_path: Path):
    store, _ = _manifest(tmp_path)

    with pytest.raises(LabSafetyError, match="max attempts must be 1-10"):
        audit_sweep_residue(
            _AuditClient(),  # type: ignore[arg-type]
            store,
            max_attempts=11,
        )
