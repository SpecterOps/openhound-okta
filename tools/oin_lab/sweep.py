"""Offline campaign planning and status for guarded OIN active traces."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import time
from typing import Any
from urllib.parse import urlsplit

from .lab import (
    LabSafetyError,
    OktaApiError,
    OktaLabClient,
    OktaNotFound,
    ProbeCase,
    RunStore,
    _external_state_root,
    _now,
    _write_private_json_atomic,
    probe_label,
    select_cases,
    validate_run_id,
)


SWEEP_SCHEMA_VERSION = 1
ACTIVE_TRACE_HEARTBEAT_GRACE = timedelta(minutes=10)
DEFAULT_AUDIT_MAX_ATTEMPTS = 4
MAX_AUDIT_MAX_ATTEMPTS = 10


def _audit_retry_delay(
    error: OktaApiError,
    attempt: int,
    *,
    clock: Callable[[], float],
) -> float:
    delay = float(2 ** (attempt - 1))
    retry_after = error.response.headers.get("Retry-After")
    if retry_after is not None:
        try:
            delay = max(delay, float(retry_after))
        except ValueError:
            pass
    reset_at = error.response.headers.get("X-Rate-Limit-Reset")
    if reset_at is not None:
        try:
            delay = max(delay, float(reset_at) - clock() + 0.25)
        except ValueError:
            pass
    return min(60.0, max(0.0, delay))


def _audit_read(
    operation: Callable[[], Any],
    *,
    max_attempts: int,
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> Any:
    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except OktaApiError as error:
            if error.status_code != 429 or attempt == max_attempts:
                raise
            sleep(_audit_retry_delay(error, attempt, clock=clock))
    raise AssertionError("residue audit retry loop exhausted")  # pragma: no cover


def select_sweep_cases(
    cases: Sequence[ProbeCase],
    requested_ids: Sequence[str],
    *,
    include_discovery: bool,
) -> tuple[ProbeCase, ...]:
    """Select an explicit list or every runnable case for a campaign."""
    if len(requested_ids) != len(set(requested_ids)):
        raise LabSafetyError("duplicate probe case requested for sweep")
    if requested_ids:
        return select_cases(
            cases,
            requested_ids,
            include_discovery=include_discovery,
        )
    readiness = {"ready", "discovery"} if include_discovery else {"ready"}
    return tuple(case for case in cases if case.readiness in readiness)


class SweepStore:
    """Immutable external manifest for a sequence of one-case active traces."""

    def __init__(self, root: Path, tenant_url: str, sweep_id: str):
        run_store = RunStore(root, tenant_url, validate_run_id(sweep_id))
        self.root = _external_state_root(root)
        self.tenant_url = run_store.tenant_url
        self.sweep_id = run_store.run_id
        tenant_key = hashlib.sha256(self.tenant_url.encode()).hexdigest()[:16]
        self.directory = self.root / tenant_key / "sweeps" / self.sweep_id
        self.manifest_path = self.directory / "manifest.json"

    def load_or_create(
        self,
        cases: Sequence[ProbeCase],
        *,
        matrix_path: Path,
        matrix_sha256: str,
        include_discovery: bool,
    ) -> dict[str, Any]:
        expected_cases = self._case_records(cases)
        if self.manifest_path.exists():
            manifest = self.load()
            if (
                manifest["matrix_sha256"] != matrix_sha256
                or manifest["matrix_path"] != str(matrix_path.resolve())
                or manifest["include_discovery"] is not include_discovery
                or manifest["cases"] != expected_cases
            ):
                raise LabSafetyError(
                    "sweep definition changed after planning; use a new sweep ID"
                )
            return manifest

        if not expected_cases:
            raise LabSafetyError("OIN sweep contains no runnable cases")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        manifest = {
            "schema_version": SWEEP_SCHEMA_VERSION,
            "sweep_id": self.sweep_id,
            "tenant_url": self.tenant_url,
            "state_root": str(self.root),
            "matrix_path": str(matrix_path.resolve()),
            "matrix_sha256": matrix_sha256,
            "include_discovery": include_discovery,
            "created_at": _now(),
            "cases": expected_cases,
        }
        _write_private_json_atomic(self.manifest_path, manifest)
        return manifest

    def load(self) -> dict[str, Any]:
        try:
            manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LabSafetyError(
                f"unable to read OIN sweep manifest {self.manifest_path}: {error}"
            ) from error
        if (
            not isinstance(manifest, dict)
            or manifest.get("schema_version") != SWEEP_SCHEMA_VERSION
            or manifest.get("sweep_id") != self.sweep_id
            or manifest.get("tenant_url") != self.tenant_url
            or manifest.get("state_root") != str(self.root)
            or not isinstance(manifest.get("matrix_path"), str)
            or not isinstance(manifest.get("matrix_sha256"), str)
            or not isinstance(manifest.get("include_discovery"), bool)
            or not isinstance(manifest.get("cases"), list)
        ):
            raise LabSafetyError(
                f"invalid or mismatched OIN sweep manifest: {self.manifest_path}"
            )
        return manifest

    def _case_records(self, cases: Sequence[ProbeCase]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for sequence, case in enumerate(cases, start=1):
            run_id = validate_run_id(f"{self.sweep_id}-{sequence:03d}")
            probe_label(run_id, case)
            records.append(
                {
                    "sequence": sequence,
                    "case_id": case.case_id,
                    "app_key": case.app_key,
                    "variant": case.variant,
                    "readiness": case.readiness,
                    "purpose": case.purpose,
                    "evidence": case.evidence,
                    "settings_app": case.settings_app,
                    "app_link_label_suffix": case.app_link_label_suffix,
                    "assignment_profile": case.assignment_profile or {},
                    "run_id": run_id,
                }
            )
        return records


def _review_summary(path: Path) -> dict[str, Any]:
    try:
        review = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise LabSafetyError(
            f"unable to read sanitized trace review {path}: {error}"
        ) from error
    saml = review.get("saml") if isinstance(review, Mapping) else None
    if (
        not isinstance(review, Mapping)
        or review.get("requires_human_review") is not True
        or review.get("saml_parameter") != "SAMLResponse"
        or not isinstance(saml, Mapping)
    ):
        raise LabSafetyError(f"invalid sanitized SAML response review: {path}")
    return {
        "review_path": str(path),
        "app_link_selection": review.get("app_link_selection"),
        "request_url": review.get("request_url"),
        "request_method": review.get("request_method"),
        "message_type": saml.get("message_type"),
        "destinations_and_recipients": saml.get("destinations_and_recipients", []),
        "audiences": saml.get("audiences", []),
    }


def _status_attempt_summary(attempt: Mapping[str, Any]) -> dict[str, Any]:
    """Present pre-classification API failures using the current safe scope."""
    summary = dict(attempt)
    status_code = summary.get("okta_status_code")
    if not (
        summary.get("failure_type") == "OktaApiError"
        and summary.get("failure_scope") == "campaign"
        and status_code in {400, 403, 404}
    ):
        return summary
    category_by_status = {
        400: "catalog_configuration_required",
        403: "catalog_request_rejected",
        404: "catalog_integration_unavailable",
    }
    summary.update(
        {
            "failure_category": category_by_status[status_code],
            "failure_scope": "case",
            "classification_reconciled_from_legacy": True,
        }
    )
    return summary


def summarize_sweep(
    store: SweepStore,
    *,
    current_matrix_sha256: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Summarize local state without making Okta or other network requests."""
    observed_at = now or datetime.now(UTC)
    manifest = store.load()
    if manifest["matrix_sha256"] != current_matrix_sha256:
        raise LabSafetyError(
            "probe matrix changed after this sweep was planned; use a new sweep ID"
        )

    results: list[dict[str, Any]] = []
    unsafe = False
    running = False
    for case in manifest["cases"]:
        run_store = RunStore(store.root, store.tenant_url, case["run_id"])
        result = {
            key: case[key]
            for key in (
                "sequence",
                "case_id",
                "app_key",
                "variant",
                "readiness",
                "run_id",
            )
        }
        if not run_store.state_path.exists():
            result["status"] = "pending"
            results.append(result)
            continue

        state = run_store.load()
        if state.get("matrix_sha256") != manifest["matrix_sha256"]:
            raise LabSafetyError(f"run {case['run_id']} uses a different probe matrix")
        records = state["records"]
        if set(records) != {case["case_id"]}:
            result["status"] = "cleanup_unverified"
            result["reason"] = "run state does not contain exactly the planned case"
            unsafe = True
            results.append(result)
            continue

        record = records[case["case_id"]]
        trace = record.get("active_trace")
        if trace is not None and not isinstance(trace, Mapping):
            result["status"] = "cleanup_unverified"
            result["reason"] = "active trace state is malformed"
            unsafe = True
            results.append(result)
            continue
        trace = trace if isinstance(trace, Mapping) else {}
        app_clean = bool(record.get("deleted_at") or record.get("absent_at"))
        user_creation_started = bool(trace.get("user_create_requested_at"))
        user_clean = not user_creation_started or bool(
            trace.get("user_deleted_at") or trace.get("user_absent_at")
        )
        review_path = run_store.run_dir / "active-review" / f"{case['case_id']}.json"
        attempt = record.get("active_trace_attempt")
        attempt_summary: Mapping[str, Any] | None = None
        if isinstance(attempt, Mapping):
            attempt_summary = _status_attempt_summary(attempt)
            result["attempt"] = dict(attempt_summary)
        attempt_cleanup_incomplete = isinstance(attempt, Mapping) and (
            attempt.get("outcome") == "cleanup_incomplete"
            or attempt.get("cleanup_verified") is False
        )
        updated_at: datetime | None = None
        try:
            updated_at = datetime.fromisoformat(state["updated_at"])
        except (KeyError, TypeError, ValueError):
            pass
        heartbeat_age = (
            observed_at - updated_at
            if updated_at is not None and updated_at.tzinfo is not None
            else None
        )
        case_recently_active = (
            attempt is None
            and (not app_clean or not user_clean)
            and heartbeat_age is not None
            and timedelta(0) <= heartbeat_age <= ACTIVE_TRACE_HEARTBEAT_GRACE
        )

        if case_recently_active:
            result["status"] = "case_running"
            result["reason"] = (
                "active-trace has not completed; wait for its command session"
            )
            running = True
        elif not app_clean or not user_clean or attempt_cleanup_incomplete:
            result["status"] = "cleanup_unverified"
            result["reason"] = (
                "application cleanup is unverified"
                if not app_clean
                else (
                    "ephemeral user cleanup is unverified"
                    if not user_clean
                    else "cleanup attempt remains unverified"
                )
            )
            unsafe = True
        elif review_path.exists():
            try:
                result["evidence"] = _review_summary(review_path)
            except LabSafetyError as error:
                result["status"] = "review_invalid"
                result["reason"] = str(error)
                unsafe = True
            else:
                result["status"] = "captured_clean"
        elif (
            attempt_summary is not None
            and attempt_summary.get("failure_scope") == "campaign"
        ):
            result["status"] = "campaign_failure"
            result["reason"] = (
                "campaign-scoped failure requires operator resolution: "
                f"{attempt_summary.get('failure_category', 'unknown')}"
            )
            unsafe = True
        else:
            result["status"] = "attempted_clean_no_capture"
        results.append(result)

    counts = {
        status: sum(result["status"] == status for result in results)
        for status in (
            "pending",
            "captured_clean",
            "attempted_clean_no_capture",
            "case_running",
            "campaign_failure",
            "cleanup_unverified",
            "review_invalid",
        )
    }
    current_case = next(
        (result for result in results if result["status"] == "case_running"), None
    )
    next_case = (
        None
        if running
        else next(
            (result for result in results if result["status"] == "pending"),
            None,
        )
    )
    next_command: list[str] | None = None
    if not unsafe and next_case is not None:
        tenant_host = urlsplit(store.tenant_url).hostname
        assert tenant_host is not None
        next_command = [
            ".venv/bin/python",
            "-m",
            "tools.oin_lab",
            "--matrix",
            manifest["matrix_path"],
            "active-trace",
            "--tenant-url",
            store.tenant_url,
            "--state-root",
            str(store.root),
            "--confirm-tenant-host",
            tenant_host,
            "--run-id",
            next_case["run_id"],
            "--confirm-run-id",
            next_case["run_id"],
            "--case",
            next_case["case_id"],
        ]
        if next_case["readiness"] == "discovery":
            next_command.append("--include-discovery")
        next_command.append("--apply")

    if unsafe:
        action = (
            "stop_cleanup_or_review_unverified"
            if any(
                result["status"] in {"cleanup_unverified", "review_invalid"}
                for result in results
            )
            else "stop_campaign_failure"
        )
    elif running:
        action = "wait_for_current_case"
    elif next_case is not None:
        action = "run_exactly_one_next_command"
    else:
        action = "campaign_attempts_complete_human_review_required"
    return {
        "schema_version": SWEEP_SCHEMA_VERSION,
        "sweep_id": store.sweep_id,
        "tenant_url": store.tenant_url,
        "manifest_path": str(store.manifest_path),
        "safe_to_continue": not unsafe,
        "all_cases_attempted": not running and counts["pending"] == 0,
        "all_cases_captured": bool(results)
        and all(result["status"] == "captured_clean" for result in results),
        "operator_action": action,
        "counts": counts,
        "current_case": current_case,
        "next_case": next_case,
        "next_command": next_command,
        "results": results,
    }


def compact_sweep_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Keep iterative agent output bounded while retaining blockers and progress."""
    results = report.get("results")
    if not isinstance(results, list):
        raise LabSafetyError("OIN sweep report has no results list")
    compact = {key: value for key, value in report.items() if key != "results"}
    attempted = [
        result
        for result in results
        if isinstance(result, Mapping) and result.get("status") != "pending"
    ]
    compact["last_attempted"] = attempted[-1] if attempted else None
    compact["blocking_results"] = [
        result
        for result in results
        if isinstance(result, Mapping)
        and result.get("status")
        in {"campaign_failure", "cleanup_unverified", "review_invalid"}
    ]
    return compact


def audit_sweep_residue(
    client: OktaLabClient,
    store: SweepStore,
    *,
    max_attempts: int = DEFAULT_AUDIT_MAX_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Read back every exact campaign app label and ephemeral user login."""
    from .active_trace import ephemeral_user_login

    if not 1 <= max_attempts <= MAX_AUDIT_MAX_ATTEMPTS:
        raise LabSafetyError(
            f"residue audit max attempts must be 1-{MAX_AUDIT_MAX_ATTEMPTS}"
        )
    manifest = store.load()
    results: list[dict[str, Any]] = []
    for case in manifest["cases"]:
        probe_case = ProbeCase(
            case_id=case["case_id"],
            app_key=case["app_key"],
            variant=case["variant"],
            sign_on_mode="SAML_2_0",
            settings_app=case["settings_app"],
            readiness=case["readiness"],
            purpose=case["purpose"],
            evidence=case["evidence"],
            app_link_label_suffix=case.get("app_link_label_suffix"),
            assignment_profile=case.get("assignment_profile", {}),
        )
        label = probe_label(case["run_id"], probe_case)
        applications = _audit_read(
            lambda: client.find_applications_by_label(label),
            max_attempts=max_attempts,
            sleep=sleep,
            clock=clock,
        )
        try:
            _audit_read(
                lambda: client.get_user(
                    ephemeral_user_login(store.tenant_url, case["run_id"])
                ),
                max_attempts=max_attempts,
                sleep=sleep,
                clock=clock,
            )
        except OktaNotFound:
            user_present = False
        else:
            user_present = True
        results.append(
            {
                "sequence": case["sequence"],
                "case_id": case["case_id"],
                "run_id": case["run_id"],
                "application_matches": len(applications),
                "user_present": user_present,
            }
        )

    application_residue_count = sum(result["application_matches"] for result in results)
    user_residue_count = sum(result["user_present"] for result in results)
    return {
        "schema_version": SWEEP_SCHEMA_VERSION,
        "sweep_id": store.sweep_id,
        "tenant_url": store.tenant_url,
        "read_only": True,
        "clean": application_residue_count == 0 and user_residue_count == 0,
        "application_residue_count": application_residue_count,
        "user_residue_count": user_residue_count,
        "results": results,
    }


def compact_residue_audit(audit: Mapping[str, Any]) -> dict[str, Any]:
    """Omit clean per-case rows and retain any residue details."""
    results = audit.get("results")
    if not isinstance(results, list):
        raise LabSafetyError("OIN sweep residue audit has no results list")
    compact = {key: value for key, value in audit.items() if key != "results"}
    compact["residue_results"] = [
        result
        for result in results
        if isinstance(result, Mapping)
        and (result.get("application_matches") or result.get("user_present"))
    ]
    return compact
