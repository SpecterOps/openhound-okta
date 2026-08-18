"""Guarded temporary-app research tooling for Okta OIN route discovery.

The checked-in SQL matrix is reproducible research input. Live application state and
raw captures are deliberately stored outside the repository and are never part of the
GlobalTech range model.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any
from unicodedata import category
from urllib.parse import parse_qs, quote, urlsplit, urlunsplit

import requests

from .schema_analyzer import SchemaAnalysisError, analyze_catalog_schema_snapshot


MATRIX_PATH = Path(__file__).with_name("matrix.sql")
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_WORKSPACE_ROOT = REPOSITORY_ROOT.parent
STATE_SCHEMA_VERSION = 1
CATALOG_SCHEMA_STATE_VERSION = 1
LABEL_PREFIX = "oin-lab-"
DEFAULT_TOKEN_ENV = "OKTA_API_TOKEN"
DEFAULT_MAX_AGE_HOURS = 24
MAX_ALLOWED_AGE_HOURS = 168
DEFAULT_SCHEMA_MAX_ATTEMPTS = 4
MAX_SCHEMA_MAX_ATTEMPTS = 10
DEFAULT_SCHEMA_PROGRESS_EVERY = 100
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_APP_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_SENSITIVE_KEY = re.compile(
    r"(?:password|secret|token|certificate|private.?key|encrypted)", re.IGNORECASE
)


class MatrixError(ValueError):
    """The checked-in probe matrix violates the harness contract."""


class LabSafetyError(RuntimeError):
    """A requested live operation failed a safety invariant."""


class CaseScopedLabOutcome(LabSafetyError):
    """A researched integration cannot proceed, but the campaign may continue."""

    failure_scope = "case"

    def __init__(self, category: str, message: str):
        self.failure_category = category
        super().__init__(message)


class OktaApiError(RuntimeError):
    """An Okta Management API operation failed."""

    def __init__(self, method: str, path: str, response: requests.Response):
        self.status_code = response.status_code
        self.response = response
        self.error_code: str | None = None
        detail: dict[str, Any] | str
        try:
            body = response.json()
        except ValueError:
            detail = response.text[:1000]
        else:
            if isinstance(body, Mapping):
                error_code = body.get("errorCode")
                if isinstance(error_code, str):
                    self.error_code = error_code
                detail = {
                    key: body.get(key)
                    for key in ("errorCode", "errorSummary", "errorCauses")
                    if body.get(key) is not None
                }
            else:
                detail = "unexpected response body"
        super().__init__(
            f"Okta API {method} {path} returned {response.status_code}: {detail}"
        )


class OktaNotFound(OktaApiError):
    """The requested Okta application does not exist."""


class OktaTransportError(RuntimeError):
    """A request failed before Okta returned an HTTP response."""

    def __init__(self, method: str, path: str):
        super().__init__(f"Okta API {method} {path} failed before receiving a response")


@dataclass(frozen=True)
class ProbeCase:
    case_id: str
    app_key: str
    variant: str
    sign_on_mode: str
    settings_app: dict[str, Any]
    readiness: str
    purpose: str
    evidence: str
    app_link_label_suffix: str | None = None
    assignment_profile: dict[str, Any] | None = None


@dataclass(frozen=True)
class CatalogSchemaCaptureResult:
    snapshot_path: Path
    analysis_path: Path
    target_count: int
    captured_count: int
    missing_count: int
    captured_this_run: int


def _now() -> str:
    return datetime.now(UTC).isoformat()


def normalize_tenant_url(value: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or any(
            character.isspace() or category(character).startswith("C")
            for character in value
        )
    ):
        raise LabSafetyError("tenant URL must be an exact HTTPS origin")
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise LabSafetyError("tenant URL must be a valid HTTPS origin") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise LabSafetyError("tenant URL must be an exact HTTPS origin")
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def validate_run_id(value: str) -> str:
    if not _SLUG.fullmatch(value):
        raise LabSafetyError(
            "run ID must be a lowercase letter/digit slug up to 64 characters"
        )
    return value


def probe_label(run_id: str, case: ProbeCase) -> str:
    label = f"{LABEL_PREFIX}{validate_run_id(run_id)}-{case.case_id}"
    if len(label) > 100:
        raise LabSafetyError(f"probe label exceeds 100 characters: {label}")
    return label


def load_cases(path: Path = MATRIX_PATH) -> tuple[ProbeCase, ...]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(path.read_text(encoding="utf-8"))
        metadata = connection.execute(
            "SELECT value FROM matrix_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if metadata is None or metadata["value"] != "3":
            raise MatrixError("matrix schema_version must be 3")
        rows = connection.execute(
            """
            SELECT probe.case_id, probe.app_key, probe.variant,
                   probe.sign_on_mode, probe.settings_app_json,
                   probe.readiness, probe.purpose, probe.evidence,
                   active.app_link_label_suffix,
                   COALESCE(active.assignment_profile_json, '{}')
                     AS assignment_profile_json
            FROM oin_probe_cases AS probe
            LEFT JOIN oin_probe_active_options AS active
              ON active.case_id = probe.case_id
            ORDER BY probe.app_key, probe.case_id
            """
        ).fetchall()
    except (OSError, sqlite3.Error) as error:
        raise MatrixError(f"unable to load OIN probe matrix {path}: {error}") from error
    finally:
        connection.close()

    cases: list[ProbeCase] = []
    for row in rows:
        case_id = row["case_id"]
        app_key = row["app_key"]
        if not _SLUG.fullmatch(case_id):
            raise MatrixError(f"invalid case_id: {case_id}")
        if not _APP_KEY.fullmatch(app_key):
            raise MatrixError(f"invalid app_key for {case_id}: {app_key}")
        if row["readiness"] not in {"ready", "discovery", "blocked"}:
            raise MatrixError(f"invalid readiness for {case_id}: {row['readiness']}")
        try:
            settings_app = json.loads(row["settings_app_json"])
            assignment_profile = json.loads(row["assignment_profile_json"])
        except json.JSONDecodeError as error:
            raise MatrixError(f"invalid JSON input for {case_id}") from error
        if not isinstance(settings_app, dict):
            raise MatrixError(f"settings JSON for {case_id} must be an object")
        if not isinstance(assignment_profile, dict):
            raise MatrixError(
                f"assignment profile JSON for {case_id} must be an object"
            )
        if any(
            not isinstance(key, str) or _SENSITIVE_KEY.search(key)
            for key in assignment_profile
        ):
            raise MatrixError(
                f"assignment profile for {case_id} has an invalid property"
            )
        app_link_label_suffix = row["app_link_label_suffix"]
        if app_link_label_suffix is not None and (
            not isinstance(app_link_label_suffix, str)
            or not app_link_label_suffix.startswith(" ")
            or app_link_label_suffix != app_link_label_suffix.strip("\r\n\t")
            or len(app_link_label_suffix) > 80
            or any(
                category(character).startswith("C")
                for character in app_link_label_suffix
            )
        ):
            raise MatrixError(f"invalid app-link label suffix for {case_id}")
        cases.append(
            ProbeCase(
                case_id=case_id,
                app_key=app_key,
                variant=row["variant"],
                sign_on_mode=row["sign_on_mode"],
                settings_app=settings_app,
                readiness=row["readiness"],
                purpose=row["purpose"],
                evidence=row["evidence"],
                app_link_label_suffix=app_link_label_suffix,
                assignment_profile=assignment_profile,
            )
        )
    if not cases:
        raise MatrixError("OIN probe matrix is empty")
    return tuple(cases)


def load_popular_saml_app_keys(path: Path = MATRIX_PATH) -> tuple[str, ...]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(path.read_text(encoding="utf-8"))
        rows = connection.execute(
            """
            SELECT DISTINCT app_key
            FROM popular_app_catalog_targets
            WHERE disposition = 'saml_candidate'
            ORDER BY app_key
            """
        ).fetchall()
    except (OSError, sqlite3.Error) as error:
        raise MatrixError(
            f"unable to load popular OIN targets {path}: {error}"
        ) from error
    finally:
        connection.close()

    app_keys = tuple(row["app_key"] for row in rows)
    if not app_keys or any(
        not isinstance(app_key, str) or not _APP_KEY.fullmatch(app_key)
        for app_key in app_keys
    ):
        raise MatrixError("popular SAML catalog targets contain an invalid app key")
    return app_keys


def select_cases(
    cases: Sequence[ProbeCase],
    requested_ids: Sequence[str],
    *,
    include_discovery: bool,
) -> tuple[ProbeCase, ...]:
    by_id = {case.case_id: case for case in cases}
    unknown = sorted(set(requested_ids) - set(by_id))
    if unknown:
        raise MatrixError(f"unknown probe case(s): {', '.join(unknown)}")
    selected = (
        [by_id[case_id] for case_id in requested_ids]
        if requested_ids
        else [case for case in cases if case.readiness == "ready"]
    )
    blocked = [case.case_id for case in selected if case.readiness == "blocked"]
    if blocked:
        raise LabSafetyError(
            "blocked probe case(s) cannot be created: " + ", ".join(blocked)
        )
    deferred = [case.case_id for case in selected if case.readiness == "discovery"]
    if deferred and not include_discovery:
        raise LabSafetyError(
            "discovery probe case(s) require --include-discovery: "
            + ", ".join(deferred)
        )
    return tuple(selected)


def build_application_payload(case: ProbeCase, run_id: str) -> dict[str, Any]:
    return {
        "name": case.app_key,
        "label": probe_label(run_id, case),
        "signOnMode": case.sign_on_mode,
        "settings": {"app": dict(case.settings_app)},
    }


def _synthetic_catalog_value(
    attribute: Mapping[str, Any], run_id: str
) -> tuple[Any, str] | None:
    enum = attribute.get("enum")
    if isinstance(enum, list):
        selected = next(
            (
                value
                for value in enum
                if value is not None and isinstance(value, (str, int, float, bool))
            ),
            None,
        )
        if selected is not None:
            return selected, "first_catalog_enum"

    attribute_type = attribute.get("type")
    if attribute_type == "boolean":
        return False, "boolean_false"
    if attribute_type == "integer":
        return 1, "integer_one"
    if attribute_type == "number":
        return 1.0, "number_one"
    if attribute_type != "string":
        return None

    name = attribute.get("name")
    if not isinstance(name, str):
        return None
    slug = f"oin-lab-{hashlib.sha256(run_id.encode()).hexdigest()[:12]}"
    if attribute.get("format") == "uri":
        return f"https://{slug}.invalid/{name.casefold()}", "reserved_invalid_uri"
    if "email" in name.casefold():
        return f"{slug}@example.invalid", "reserved_invalid_email"
    return slug, "deterministic_lab_slug"


def _prepare_catalog_case(
    client: OktaLabClient,
    store: RunStore,
    state: dict[str, Any],
    case: ProbeCase,
    record: dict[str, Any],
) -> ProbeCase:
    application = client.get_catalog_application(case.app_key)
    analysis = analyze_catalog_schema_snapshot(
        {"schema_version": 1, "applications": [application]}
    )["applications"][0]
    settings_app = dict(case.settings_app)
    missing = [
        attribute
        for attribute in analysis["attributes"]
        if attribute.get("required") is True
        and not attribute.get("has_default")
        and (
            settings_app.get(attribute.get("name")) is None
            or settings_app.get(attribute.get("name")) == ""
        )
    ]
    explicit_route_fields = sorted(
        attribute["name"]
        for attribute in missing
        if "explicit_route_input" in attribute.get("route_signals", [])
    )
    preparation: dict[str, Any] = {
        "schema_analysis_version": 1,
        "research_disposition": analysis["classification"]["research_disposition"],
        "required_explicit_route_fields": explicit_route_fields,
        "synthesized_fields": [],
    }
    record["catalog_schema_preparation"] = preparation
    store.save(state)
    if explicit_route_fields:
        raise CaseScopedLabOutcome(
            "required_explicit_route_input",
            "catalog integration requires explicit route input: "
            + ", ".join(explicit_route_fields),
        )

    unresolved: list[str] = []
    for attribute in missing:
        generated = _synthetic_catalog_value(attribute, store.run_id)
        name = attribute.get("name")
        if generated is None or not isinstance(name, str):
            if isinstance(name, str):
                unresolved.append(name)
            continue
        value, strategy = generated
        settings_app[name] = value
        preparation["synthesized_fields"].append(
            {
                "name": name,
                "section": attribute.get("section"),
                "strategy": strategy,
            }
        )
    if unresolved:
        preparation["unresolved_required_fields"] = sorted(unresolved)
        store.save(state)
        raise CaseScopedLabOutcome(
            "unsupported_required_catalog_input",
            "catalog integration has unsupported required input",
        )
    preparation["settings_sha256"] = _value_digest(settings_app)
    store.save(state)
    return replace(case, settings_app=settings_app)


def default_state_root() -> Path:
    xdg_state_home = os.environ.get("XDG_STATE_HOME")
    if xdg_state_home:
        return Path(xdg_state_home) / "openhound-okta" / "oin-lab"
    return Path.home() / ".local" / "state" / "openhound-okta" / "oin-lab"


def _external_state_root(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    if (
        resolved == REPOSITORY_WORKSPACE_ROOT
        or REPOSITORY_WORKSPACE_ROOT in resolved.parents
    ):
        raise LabSafetyError("state root must be outside the repository workspace")
    return resolved


def _write_private_text(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)


def _json_text(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _write_private_json_atomic(path: Path, value: Any) -> None:
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    _write_private_text(temporary_path, _json_text(value))
    temporary_path.replace(path)


def _value_digest(value: Any) -> str:
    serialized = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


class RunStore:
    def __init__(self, root: Path, tenant_url: str, run_id: str):
        self.tenant_url = normalize_tenant_url(tenant_url)
        self.run_id = validate_run_id(run_id)
        tenant_key = hashlib.sha256(self.tenant_url.encode()).hexdigest()[:16]
        self.run_dir = _external_state_root(root) / tenant_key / self.run_id
        self.state_path = self.run_dir / "state.json"

    def load_or_create(
        self,
        matrix_digest: str,
        *,
        max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
    ) -> dict[str, Any]:
        if not 1 <= max_age_hours <= MAX_ALLOWED_AGE_HOURS:
            raise LabSafetyError(f"max app age must be 1-{MAX_ALLOWED_AGE_HOURS} hours")
        if self.state_path.exists():
            existing_state = json.loads(self.state_path.read_text(encoding="utf-8"))
            self._validate_state(existing_state)
            if existing_state["matrix_sha256"] != matrix_digest:
                raise LabSafetyError(
                    "probe matrix changed after this run began; use a new run ID"
                )
            return existing_state
        created_at = datetime.now(UTC)
        state: dict[str, Any] = {
            "schema_version": STATE_SCHEMA_VERSION,
            "run_id": self.run_id,
            "tenant_url": self.tenant_url,
            "matrix_sha256": matrix_digest,
            "created_at": created_at.isoformat(),
            "expires_at": (created_at + timedelta(hours=max_age_hours)).isoformat(),
            "updated_at": _now(),
            "records": {},
        }
        self.save(state)
        return state

    def load(self) -> dict[str, Any]:
        if not self.state_path.exists():
            raise LabSafetyError(f"run state does not exist: {self.state_path}")
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self._validate_state(state)
        return state

    def _validate_state(self, state: Mapping[str, Any]) -> None:
        if (
            state.get("schema_version") != STATE_SCHEMA_VERSION
            or state.get("run_id") != self.run_id
            or state.get("tenant_url") != self.tenant_url
            or not isinstance(state.get("expires_at"), str)
            or not isinstance(state.get("records"), dict)
        ):
            raise LabSafetyError(f"invalid or mismatched run state: {self.state_path}")

    def save(self, state: dict[str, Any]) -> None:
        self.run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.run_dir.chmod(0o700)
        state["updated_at"] = _now()
        temporary_path = self.state_path.with_suffix(".json.tmp")
        _write_private_text(
            temporary_path,
            json.dumps(state, indent=2, sort_keys=True) + "\n",
        )
        temporary_path.replace(self.state_path)

    def write_capture(self, category: str, case_id: str, content: str) -> Path:
        directory = self.run_dir / category
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        path = directory / f"{case_id}.json"
        _write_private_text(path, content)
        return path

    def write_metadata(self, case_id: str, content: str) -> Path:
        directory = self.run_dir / "raw"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory.chmod(0o700)
        path = directory / f"{case_id}.metadata.xml"
        _write_private_text(path, content)
        return path


def load_saml_catalog_app_keys(path: Path) -> tuple[tuple[str, ...], str]:
    try:
        content = path.read_bytes()
        snapshot = json.loads(content)
    except (OSError, json.JSONDecodeError) as error:
        raise LabSafetyError(
            f"unable to read catalog snapshot {path}: {error}"
        ) from error
    if not isinstance(snapshot, Mapping) or not isinstance(
        snapshot.get("applications"), list
    ):
        raise LabSafetyError("catalog snapshot applications must be a list")

    app_keys: list[str] = []
    seen: set[str] = set()
    for index, application in enumerate(snapshot["applications"]):
        if not isinstance(application, Mapping):
            raise LabSafetyError(f"catalog application {index} must be an object")
        sign_on_modes = application.get("signOnModes")
        if not isinstance(sign_on_modes, list) or not all(
            isinstance(mode, str) for mode in sign_on_modes
        ):
            raise LabSafetyError(f"catalog application {index} has invalid signOnModes")
        if "SAML_2_0" not in sign_on_modes:
            continue
        app_key = application.get("name")
        if not isinstance(app_key, str) or not _APP_KEY.fullmatch(app_key):
            raise LabSafetyError(f"catalog application {index} has an invalid app key")
        if app_key in seen:
            raise LabSafetyError(f"duplicate SAML catalog application: {app_key}")
        seen.add(app_key)
        app_keys.append(app_key)

    if not app_keys:
        raise LabSafetyError("catalog snapshot contains no SAML applications")
    return tuple(sorted(app_keys)), hashlib.sha256(content).hexdigest()


class CatalogSchemaStore:
    """External checkpoint storage for a read-only catalog schema sweep."""

    def __init__(self, root: Path, tenant_url: str, snapshot_id: str):
        self.tenant_url = normalize_tenant_url(tenant_url)
        self.snapshot_id = validate_run_id(snapshot_id)
        tenant_key = hashlib.sha256(self.tenant_url.encode()).hexdigest()[:16]
        self.directory = (
            _external_state_root(root)
            / tenant_key
            / "catalog-schemas"
            / self.snapshot_id
        )
        self.raw_directory = self.directory / "raw"
        self.state_path = self.directory / "state.json"
        self.snapshot_path = self.directory / "applications.json"
        self.analysis_path = self.directory / "schema-analysis.json"

    def load_or_create(
        self,
        app_keys: Sequence[str],
        *,
        target_source: Mapping[str, Any],
        resume: bool,
    ) -> dict[str, Any]:
        normalized_app_keys = tuple(sorted(set(app_keys)))
        if (
            not normalized_app_keys
            or len(normalized_app_keys) != len(app_keys)
            or any(not _APP_KEY.fullmatch(app_key) for app_key in normalized_app_keys)
        ):
            raise LabSafetyError("schema capture targets contain invalid app keys")
        target_source_value = dict(target_source)
        target_digest = _value_digest(normalized_app_keys)

        if self.state_path.exists():
            if not resume:
                raise LabSafetyError(
                    "catalog schema capture already exists; pass --resume or use a "
                    "new snapshot ID"
                )
            existing_state = self.load()
            if (
                existing_state["target_app_keys"] != list(normalized_app_keys)
                or existing_state["target_app_keys_sha256"] != target_digest
                or existing_state["target_source"] != target_source_value
            ):
                raise LabSafetyError(
                    "catalog schema targets changed after capture began; use a new "
                    "snapshot ID"
                )
            return existing_state

        if resume:
            raise LabSafetyError(
                f"catalog schema capture state does not exist: {self.state_path}"
            )
        if self.directory.exists() and any(self.directory.iterdir()):
            raise LabSafetyError(
                "catalog schema capture directory is non-empty without resumable "
                "state; use a new snapshot ID"
            )

        state: dict[str, Any] = {
            "schema_version": CATALOG_SCHEMA_STATE_VERSION,
            "research_scope": "openhound-okta-ephemeral-oin-lab",
            "tenant_url": self.tenant_url,
            "snapshot_id": self.snapshot_id,
            "target_source": target_source_value,
            "target_app_keys": list(normalized_app_keys),
            "target_app_keys_sha256": target_digest,
            "target_count": len(normalized_app_keys),
            "created_at": _now(),
            "updated_at": _now(),
            "completed_at": None,
            "records": {},
            "missing": {},
        }
        self.save(state)
        return state

    def load(self) -> dict[str, Any]:
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LabSafetyError(
                f"unable to read catalog schema state {self.state_path}: {error}"
            ) from error
        self._validate_state(state)
        return state

    def _validate_state(self, state: Any) -> None:
        if (
            not isinstance(state, Mapping)
            or state.get("schema_version") != CATALOG_SCHEMA_STATE_VERSION
            or state.get("tenant_url") != self.tenant_url
            or state.get("snapshot_id") != self.snapshot_id
            or not isinstance(state.get("target_source"), Mapping)
            or not isinstance(state.get("target_app_keys"), list)
            or not isinstance(state.get("target_app_keys_sha256"), str)
            or not isinstance(state.get("records"), dict)
            or not isinstance(state.get("missing"), dict)
        ):
            raise LabSafetyError(
                f"invalid or mismatched catalog schema state: {self.state_path}"
            )
        app_keys = state["target_app_keys"]
        if (
            state.get("target_count") != len(app_keys)
            or _value_digest(tuple(app_keys)) != state["target_app_keys_sha256"]
            or any(not isinstance(app_key, str) for app_key in app_keys)
            or set(state["records"]) - set(app_keys)
            or set(state["missing"]) - set(app_keys)
            or set(state["records"]) & set(state["missing"])
        ):
            raise LabSafetyError(f"corrupt catalog schema state: {self.state_path}")

    def save(self, state: dict[str, Any]) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        state["updated_at"] = _now()
        _write_private_json_atomic(self.state_path, state)

    def _read_capture(self, app_key: str) -> tuple[dict[str, Any], str, str]:
        path = self.raw_directory / f"{app_key}.json"
        try:
            content = path.read_bytes()
            wrapper = json.loads(content)
        except (OSError, json.JSONDecodeError) as error:
            raise LabSafetyError(
                f"invalid catalog schema checkpoint {path}: {error}"
            ) from error
        if (
            not isinstance(wrapper, Mapping)
            or wrapper.get("schema_version") != 1
            or not isinstance(wrapper.get("captured_at"), str)
            or not isinstance(wrapper.get("application"), dict)
            or wrapper["application"].get("name") != app_key
        ):
            raise LabSafetyError(f"invalid catalog schema checkpoint identity: {path}")
        return (
            wrapper["application"],
            wrapper["captured_at"],
            hashlib.sha256(content).hexdigest(),
        )

    def reconcile(self, state: dict[str, Any]) -> int:
        if not self.raw_directory.exists():
            return 0
        target_app_keys = set(state["target_app_keys"])
        unexpected = sorted(
            path.name
            for path in self.raw_directory.glob("*.json")
            if path.stem not in target_app_keys
        )
        if unexpected:
            raise LabSafetyError(
                "unexpected catalog schema checkpoint(s): " + ", ".join(unexpected)
            )

        recovered = 0
        for app_key in state["target_app_keys"]:
            path = self.raw_directory / f"{app_key}.json"
            record = state["records"].get(app_key)
            if record is None and not path.exists():
                continue
            _, captured_at, digest = self._read_capture(app_key)
            if record is not None:
                if (
                    not isinstance(record, Mapping)
                    or record.get("captured_at") != captured_at
                    or record.get("sha256") != digest
                ):
                    raise LabSafetyError(
                        f"catalog schema checkpoint changed after capture: {app_key}"
                    )
                continue
            state["records"][app_key] = {
                "captured_at": captured_at,
                "sha256": digest,
            }
            state["missing"].pop(app_key, None)
            recovered += 1
        if recovered:
            self.save(state)
        return recovered

    def write_capture(
        self, state: dict[str, Any], app_key: str, application: Mapping[str, Any]
    ) -> None:
        if (
            app_key not in state["target_app_keys"]
            or application.get("name") != app_key
        ):
            raise LabSafetyError(
                f"catalog schema response identity did not match {app_key}"
            )
        self.raw_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.raw_directory.chmod(0o700)
        captured_at = _now()
        path = self.raw_directory / f"{app_key}.json"
        wrapper = {
            "schema_version": 1,
            "captured_at": captured_at,
            "application": dict(application),
        }
        _write_private_json_atomic(path, wrapper)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        state["records"][app_key] = {
            "captured_at": captured_at,
            "sha256": digest,
        }
        state["missing"].pop(app_key, None)
        self.save(state)

    def record_missing(self, state: dict[str, Any], app_key: str) -> None:
        if app_key not in state["target_app_keys"]:
            raise LabSafetyError(f"unrecognized catalog schema target: {app_key}")
        state["missing"][app_key] = {
            "observed_at": _now(),
            "status_code": 404,
        }
        self.save(state)

    def materialize(self, state: dict[str, Any]) -> tuple[Path, Path]:
        applications: list[dict[str, Any]] = []
        captured_at_values: list[str] = []
        for app_key in state["target_app_keys"]:
            record = state["records"].get(app_key)
            if record is None:
                if app_key in state["missing"]:
                    continue
                raise LabSafetyError(f"catalog schema capture is incomplete: {app_key}")
            application, captured_at, digest = self._read_capture(app_key)
            if (
                record.get("captured_at") != captured_at
                or record.get("sha256") != digest
            ):
                raise LabSafetyError(
                    f"catalog schema checkpoint changed after capture: {app_key}"
                )
            applications.append(application)
            captured_at_values.append(captured_at)

        payload = {
            "schema_version": 1,
            "captured_at": max(captured_at_values, default=state["created_at"]),
            "source": "Okta Catalog API /api/v1/catalog/apps/{name}?expand=schema",
            "target_source": state["target_source"],
            "target_application_count": state["target_count"],
            "application_count": len(applications),
            "missing_application_count": len(state["missing"]),
            "missing_applications": [
                {
                    "app_key": app_key,
                    "status_code": state["missing"][app_key]["status_code"],
                }
                for app_key in state["target_app_keys"]
                if app_key in state["missing"]
            ],
            "applications": applications,
        }
        _write_private_json_atomic(self.snapshot_path, payload)
        analysis = analyze_catalog_schema_snapshot(payload)
        _write_private_json_atomic(self.analysis_path, analysis)
        if state.get("completed_at") is None:
            state["completed_at"] = _now()
            self.save(state)
        return self.snapshot_path, self.analysis_path


class OktaLabClient:
    """Minimal client for reversible OIN application probes.

    POST is intentionally not retried because an ambiguous retry could create a
    duplicate app. Only read-only catalog schema GETs use bounded retries.
    """

    def __init__(
        self,
        tenant_url: str,
        token: str,
        *,
        session: requests.Session | None = None,
        timeout_seconds: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ):
        self.tenant_url = normalize_tenant_url(tenant_url)
        if not token or any(category(character).startswith("C") for character in token):
            raise LabSafetyError("Okta API token is missing or malformed")
        self._token = token
        self._session = session or requests.Session()
        self._timeout_seconds = timeout_seconds
        self._sleep = sleep
        self._clock = clock

    def _request(
        self,
        method: str,
        path: str,
        *,
        expected: set[int],
        params: Mapping[str, Any] | None = None,
        body: Mapping[str, Any] | None = None,
        accept: str = "application/json",
        content_type: str | None = "application/json",
    ) -> requests.Response:
        headers = {
            "Accept": accept,
            "Authorization": f"SSWS {self._token}",
            "User-Agent": "openhound-okta-oin-lab/1",
        }
        if content_type is not None:
            headers["Content-Type"] = content_type
        try:
            response = self._session.request(
                method,
                f"{self.tenant_url}{path}",
                headers=headers,
                params=params,
                json=body,
                timeout=self._timeout_seconds,
            )
        except requests.RequestException as error:
            raise OktaTransportError(method, path) from error
        if response.status_code == 404:
            raise OktaNotFound(method, path, response)
        if response.status_code not in expected:
            raise OktaApiError(method, path, response)
        return response

    def create_application(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/api/v1/apps",
            expected={200},
            params={"activate": "false"},
            body=payload,
        )
        result = response.json()
        if not isinstance(result, dict):
            raise OktaApiError("POST", "/api/v1/apps", response)
        return result

    def get_application(self, app_id: str) -> dict[str, Any]:
        response = self._request("GET", f"/api/v1/apps/{app_id}", expected={200})
        result = response.json()
        if not isinstance(result, dict):
            raise OktaApiError("GET", f"/api/v1/apps/{app_id}", response)
        return result

    def activate_application(self, app_id: str) -> None:
        self._request(
            "POST",
            f"/api/v1/apps/{app_id}/lifecycle/activate",
            expected={200},
            body={},
        )

    def deactivate_application(self, app_id: str) -> None:
        self._request(
            "POST",
            f"/api/v1/apps/{app_id}/lifecycle/deactivate",
            expected={200},
            body={},
        )

    def list_application_users(self, app_id: str) -> tuple[dict[str, Any], ...]:
        response = self._request(
            "GET",
            f"/api/v1/apps/{app_id}/users",
            expected={200},
            params={"limit": 200},
        )
        users = response.json()
        if not isinstance(users, list) or not all(
            isinstance(user, dict) for user in users
        ):
            raise OktaApiError("GET", f"/api/v1/apps/{app_id}/users", response)
        return tuple(users)

    def assign_application_user(
        self,
        app_id: str,
        user_id: str,
        login: str,
        *,
        profile: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "id": user_id,
            "scope": "USER",
            "credentials": {"userName": login},
        }
        if profile:
            body["profile"] = dict(profile)
        response = self._request(
            "POST",
            f"/api/v1/apps/{app_id}/users",
            expected={200},
            body=body,
        )
        assignment = response.json()
        if not isinstance(assignment, dict):
            raise OktaApiError("POST", f"/api/v1/apps/{app_id}/users", response)
        return assignment

    def unassign_application_user(self, app_id: str, user_id: str) -> None:
        self._request(
            "DELETE",
            f"/api/v1/apps/{app_id}/users/{user_id}",
            expected={204},
        )

    def get_user(self, user_id_or_login: str) -> dict[str, Any]:
        encoded = quote(user_id_or_login, safe="")
        response = self._request("GET", f"/api/v1/users/{encoded}", expected={200})
        user = response.json()
        if not isinstance(user, dict):
            raise OktaApiError("GET", f"/api/v1/users/{encoded}", response)
        return user

    def create_user(self, profile: Mapping[str, Any], password: str) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/api/v1/users",
            expected={200},
            params={"activate": "true"},
            body={
                "profile": dict(profile),
                "credentials": {"password": {"value": password}},
            },
        )
        user = response.json()
        if not isinstance(user, dict):
            raise OktaApiError("POST", "/api/v1/users", response)
        return user

    def list_user_roles(self, user_id: str) -> tuple[dict[str, Any], ...]:
        response = self._request(
            "GET", f"/api/v1/users/{user_id}/roles", expected={200}
        )
        roles = response.json()
        if not isinstance(roles, list) or not all(
            isinstance(role, dict) for role in roles
        ):
            raise OktaApiError("GET", f"/api/v1/users/{user_id}/roles", response)
        return tuple(roles)

    def list_user_groups(self, user_id: str) -> tuple[dict[str, Any], ...]:
        response = self._request(
            "GET", f"/api/v1/users/{user_id}/groups", expected={200}
        )
        groups = response.json()
        if not isinstance(groups, list) or not all(
            isinstance(group, dict) for group in groups
        ):
            raise OktaApiError("GET", f"/api/v1/users/{user_id}/groups", response)
        return tuple(groups)

    def list_group_applications(self, group_id: str) -> tuple[dict[str, Any], ...]:
        response = self._request(
            "GET",
            f"/api/v1/groups/{group_id}/apps",
            expected={200},
            params={"limit": 200},
        )
        applications = response.json()
        if not isinstance(applications, list) or not all(
            isinstance(application, dict) for application in applications
        ):
            raise OktaApiError("GET", f"/api/v1/groups/{group_id}/apps", response)
        return tuple(applications)

    def list_user_app_links(self, user_id: str) -> tuple[dict[str, Any], ...]:
        response = self._request(
            "GET", f"/api/v1/users/{user_id}/appLinks", expected={200}
        )
        links = response.json()
        if not isinstance(links, list) or not all(
            isinstance(link, dict) for link in links
        ):
            raise OktaApiError("GET", f"/api/v1/users/{user_id}/appLinks", response)
        return tuple(links)

    def enroll_totp_factor(self, user_id: str) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/api/v1/users/{user_id}/factors",
            expected={200},
            body={"factorType": "token:software:totp", "provider": "GOOGLE"},
        )
        factor = response.json()
        if not isinstance(factor, dict):
            raise OktaApiError("POST", f"/api/v1/users/{user_id}/factors", response)
        return factor

    def activate_factor(
        self, user_id: str, factor_id: str, pass_code: str
    ) -> dict[str, Any]:
        path = f"/api/v1/users/{user_id}/factors/{factor_id}/lifecycle/activate"
        response = self._request(
            "POST", path, expected={200}, body={"passCode": pass_code}
        )
        factor = response.json()
        if not isinstance(factor, dict):
            raise OktaApiError("POST", path, response)
        return factor

    def deactivate_user(self, user_id: str) -> None:
        self._request(
            "POST",
            f"/api/v1/users/{user_id}/lifecycle/deactivate",
            expected={200},
            body={},
        )

    def delete_user(self, user_id: str) -> None:
        self._request("DELETE", f"/api/v1/users/{user_id}", expected={204})

    def find_applications_by_label(self, label: str) -> list[dict[str, Any]]:
        response = self._request(
            "GET",
            "/api/v1/apps",
            expected={200},
            params={"q": label, "includeNonDeleted": "true", "limit": 200},
        )
        result = response.json()
        if not isinstance(result, list):
            raise OktaApiError("GET", "/api/v1/apps", response)
        return [
            item
            for item in result
            if isinstance(item, dict) and item.get("label") == label
        ]

    def list_catalog_applications(self) -> tuple[dict[str, Any], ...]:
        applications: list[dict[str, Any]] = []
        after: str | None = None
        seen_cursors: set[str] = set()
        while True:
            params: dict[str, Any] = {"limit": 200}
            if after is not None:
                params["after"] = after
            response = self._request(
                "GET",
                "/api/v1/catalog/apps",
                expected={200},
                params=params,
            )
            page = response.json()
            if not isinstance(page, list) or not all(
                isinstance(item, dict) for item in page
            ):
                raise OktaApiError("GET", "/api/v1/catalog/apps", response)
            applications.extend(page)

            next_link = response.links.get("next", {}).get("url")
            if not next_link:
                return tuple(applications)
            parsed = urlsplit(next_link)
            if (
                urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
                != self.tenant_url
                or parsed.path != "/api/v1/catalog/apps"
            ):
                raise LabSafetyError("catalog pagination left the confirmed tenant")
            cursor_values = parse_qs(parsed.query).get("after", [])
            if len(cursor_values) != 1 or cursor_values[0] in seen_cursors:
                raise LabSafetyError("catalog pagination returned an invalid cursor")
            after = cursor_values[0]
            seen_cursors.add(after)

    def _catalog_retry_delay(
        self, error: OktaApiError | OktaTransportError, attempt: int
    ) -> float:
        delay = float(2 ** (attempt - 1))
        if isinstance(error, OktaApiError):
            retry_after = error.response.headers.get("Retry-After")
            if retry_after is not None:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    pass
            reset_at = error.response.headers.get("X-Rate-Limit-Reset")
            if reset_at is not None:
                try:
                    delay = max(delay, float(reset_at) - self._clock() + 0.25)
                except ValueError:
                    pass
        return min(60.0, max(0.0, delay))

    def get_catalog_application(
        self,
        app_key: str,
        *,
        max_attempts: int = DEFAULT_SCHEMA_MAX_ATTEMPTS,
    ) -> dict[str, Any]:
        if not _APP_KEY.fullmatch(app_key):
            raise LabSafetyError(f"invalid catalog application key: {app_key}")
        if not 1 <= max_attempts <= MAX_SCHEMA_MAX_ATTEMPTS:
            raise LabSafetyError(
                f"catalog schema max attempts must be 1-{MAX_SCHEMA_MAX_ATTEMPTS}"
            )
        path = f"/api/v1/catalog/apps/{app_key}"
        for attempt in range(1, max_attempts + 1):
            try:
                response = self._request(
                    "GET",
                    path,
                    expected={200},
                    params={"expand": "schema"},
                )
            except (OktaApiError, OktaTransportError) as error:
                retryable = isinstance(error, OktaTransportError) or (
                    error.status_code == 429 or 500 <= error.status_code < 600
                )
                if not retryable or attempt == max_attempts:
                    raise
                self._sleep(self._catalog_retry_delay(error, attempt))
                continue
            break
        else:  # pragma: no cover - loop either returns a response or raises
            raise AssertionError("catalog schema retry loop exhausted")
        application = response.json()
        if not isinstance(application, dict) or application.get("name") != app_key:
            raise LabSafetyError(
                f"catalog schema response identity did not match {app_key}"
            )
        return application

    def get_saml_metadata(self, app_id: str) -> str:
        response = self._request(
            "GET",
            f"/api/v1/apps/{app_id}/sso/saml/metadata",
            expected={200},
            accept="application/xml",
            content_type=None,
        )
        return response.text

    def delete_application(self, app_id: str) -> None:
        self._request("DELETE", f"/api/v1/apps/{app_id}", expected={204})


def _validate_application_identity(
    application: Mapping[str, Any],
    *,
    app_id: str | None,
    app_key: str,
    label: str,
) -> str:
    observed_id = application.get("id")
    if (
        not isinstance(observed_id, str)
        or (app_id is not None and observed_id != app_id)
        or application.get("name") != app_key
        or application.get("label") != label
    ):
        raise LabSafetyError(
            "refusing operation because the live application identity does not "
            "match the recorded OIN lab probe"
        )
    return observed_id


_OMIT = object()


def _sanitize_value(
    value: Any,
    *,
    tenant_url: str,
    app_id: str,
    label: str,
    field_name: str = "",
) -> Any:
    if _SENSITIVE_KEY.search(field_name):
        return _OMIT
    if isinstance(value, Mapping):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                continue
            cleaned = _sanitize_value(
                item,
                tenant_url=tenant_url,
                app_id=app_id,
                label=label,
                field_name=key,
            )
            if cleaned is not _OMIT:
                sanitized[key] = cleaned
        return sanitized
    if isinstance(value, list):
        return [
            cleaned
            for item in value
            if (
                cleaned := _sanitize_value(
                    item,
                    tenant_url=tenant_url,
                    app_id=app_id,
                    label=label,
                    field_name=field_name,
                )
            )
            is not _OMIT
        ]
    if isinstance(value, str):
        return (
            value.replace(tenant_url, "https://{oktaDomain}")
            .replace(app_id, "{appId}")
            .replace(label, "{probeLabel}")
        )
    return value


def public_application_snapshot(
    case: ProbeCase,
    application: Mapping[str, Any],
    *,
    tenant_url: str,
    app_id: str,
    label: str,
) -> dict[str, Any]:
    settings = application.get("settings")
    settings = settings if isinstance(settings, Mapping) else {}
    selected_settings = {
        key: settings[key] for key in ("app", "signOn") if key in settings
    }
    sanitized_settings = _sanitize_value(
        selected_settings,
        tenant_url=tenant_url,
        app_id=app_id,
        label=label,
    )
    assert isinstance(sanitized_settings, dict)
    app_settings = sanitized_settings.get("app")
    sign_on_settings = sanitized_settings.get("signOn")
    return {
        "schema_version": 1,
        "research_scope": "openhound-okta-ephemeral-oin-lab",
        "requires_human_review": True,
        "case": {
            "case_id": case.case_id,
            "app_key": case.app_key,
            "variant": case.variant,
            "matrix_readiness": case.readiness,
        },
        "application": {
            "id": "{appId}",
            "name": application.get("name"),
            "label": "{probeLabel}",
            "status": application.get("status"),
            "signOnMode": application.get("signOnMode"),
            "settings": sanitized_settings,
        },
        "observed_fields": {
            "settings.app": sorted(app_settings)
            if isinstance(app_settings, dict)
            else [],
            "settings.signOn": (
                sorted(sign_on_settings) if isinstance(sign_on_settings, dict) else []
            ),
        },
    }


def public_catalog_snapshot(
    applications: Sequence[Mapping[str, Any]],
    *,
    saml_only: bool,
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for application in applications:
        sign_on_modes = application.get("signOnModes")
        if not isinstance(sign_on_modes, list) or not all(
            isinstance(mode, str) for mode in sign_on_modes
        ):
            sign_on_modes = []
        if saml_only and "SAML_2_0" not in sign_on_modes:
            continue
        records.append(
            {
                "name": application.get("name"),
                "displayName": application.get("displayName"),
                "status": application.get("status"),
                "signOnModes": sorted(sign_on_modes),
                "features": application.get("features", []),
            }
        )
    records.sort(key=lambda item: (str(item["name"]), str(item["displayName"])))
    return {
        "schema_version": 1,
        "captured_at": _now(),
        "source": "Okta Catalog API /api/v1/catalog/apps",
        "saml_only": saml_only,
        "application_count": len(records),
        "applications": records,
    }


def write_catalog_snapshot(
    root: Path,
    tenant_url: str,
    snapshot_id: str,
    snapshot: Mapping[str, Any],
) -> Path:
    normalized_tenant_url = normalize_tenant_url(tenant_url)
    tenant_key = hashlib.sha256(normalized_tenant_url.encode()).hexdigest()[:16]
    directory = (
        _external_state_root(root)
        / tenant_key
        / "catalog"
        / validate_run_id(snapshot_id)
    )
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / "applications.json"
    _write_private_text(path, json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    return path


def write_catalog_schema_snapshot(
    root: Path,
    tenant_url: str,
    snapshot_id: str,
    applications: Sequence[Mapping[str, Any]],
) -> Path:
    normalized_tenant_url = normalize_tenant_url(tenant_url)
    tenant_key = hashlib.sha256(normalized_tenant_url.encode()).hexdigest()[:16]
    directory = (
        _external_state_root(root)
        / tenant_key
        / "catalog-schemas"
        / validate_run_id(snapshot_id)
    )
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / "applications.json"
    payload = {
        "schema_version": 1,
        "captured_at": _now(),
        "source": "Okta Catalog API /api/v1/catalog/apps/{name}?expand=schema",
        "application_count": len(applications),
        "applications": list(applications),
    }
    _write_private_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def analyze_catalog_schema_file(
    input_path: Path, output_path: Path | None = None
) -> Path:
    try:
        snapshot = json.loads(input_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SchemaAnalysisError(
            f"unable to read catalog schema snapshot {input_path}: {error}"
        ) from error
    if not isinstance(snapshot, Mapping):
        raise SchemaAnalysisError("catalog schema snapshot must be an object")

    destination = (
        (output_path or input_path.with_name("schema-analysis.json"))
        .expanduser()
        .resolve()
    )
    destination = _external_state_root(destination.parent) / destination.name
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    analysis = analyze_catalog_schema_snapshot(snapshot)
    _write_private_text(
        destination, json.dumps(analysis, indent=2, sort_keys=True) + "\n"
    )
    return destination


def capture_catalog_schemas(
    client: OktaLabClient,
    store: CatalogSchemaStore,
    app_keys: Sequence[str],
    *,
    target_source: Mapping[str, Any],
    resume: bool,
    max_attempts: int = DEFAULT_SCHEMA_MAX_ATTEMPTS,
    progress: Callable[[int, int, int, int], None] | None = None,
) -> CatalogSchemaCaptureResult:
    state = store.load_or_create(
        app_keys,
        target_source=target_source,
        resume=resume,
    )
    store.reconcile(state)
    captured_this_run = 0
    total = len(state["target_app_keys"])
    for index, app_key in enumerate(state["target_app_keys"], start=1):
        if app_key not in state["records"] and app_key not in state["missing"]:
            try:
                application = client.get_catalog_application(
                    app_key, max_attempts=max_attempts
                )
            except OktaNotFound:
                store.record_missing(state, app_key)
            else:
                store.write_capture(state, app_key, application)
                captured_this_run += 1
        if progress is not None:
            progress(index, total, len(state["records"]), len(state["missing"]))

    snapshot_path, analysis_path = store.materialize(state)
    return CatalogSchemaCaptureResult(
        snapshot_path=snapshot_path,
        analysis_path=analysis_path,
        target_count=total,
        captured_count=len(state["records"]),
        missing_count=len(state["missing"]),
        captured_this_run=captured_this_run,
    )


def _capture_application(
    client: OktaLabClient,
    store: RunStore,
    state: dict[str, Any],
    case: ProbeCase,
    record: dict[str, Any],
    *,
    include_metadata: bool,
) -> None:
    app_id = record["app_id"]
    application = client.get_application(app_id)
    _validate_application_identity(
        application,
        app_id=app_id,
        app_key=case.app_key,
        label=record["label"],
    )
    store.write_capture(
        "raw", case.case_id, json.dumps(application, indent=2, sort_keys=True) + "\n"
    )
    snapshot = public_application_snapshot(
        case,
        application,
        tenant_url=store.tenant_url,
        app_id=app_id,
        label=record["label"],
    )
    store.write_capture(
        "review", case.case_id, json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
    )
    if include_metadata:
        try:
            metadata = client.get_saml_metadata(app_id)
        except OktaNotFound:
            record["saml_metadata_status"] = "unavailable"
        else:
            store.write_metadata(case.case_id, metadata)
            record["saml_metadata_status"] = "captured"
    record["observed_status"] = application.get("status")
    record["captured_at"] = _now()
    state["records"][case.case_id] = record
    store.save(state)


def create_run(
    client: OktaLabClient,
    store: RunStore,
    cases: Sequence[ProbeCase],
    *,
    matrix_digest: str,
    include_metadata: bool = False,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
    prepare_catalog_settings: bool = False,
) -> dict[str, Any]:
    state = store.load_or_create(matrix_digest, max_age_hours=max_age_hours)
    try:
        expires_at = datetime.fromisoformat(state["expires_at"])
    except ValueError as error:
        raise LabSafetyError("run state has an invalid expires_at timestamp") from error
    if expires_at <= datetime.now(UTC):
        raise LabSafetyError(
            "run has exceeded its maximum app age; capture if needed, then cleanup"
        )
    for case in cases:
        label = probe_label(store.run_id, case)
        record = state["records"].get(case.case_id)
        if record and record.get("deleted_at"):
            raise LabSafetyError(
                f"case {case.case_id} was already deleted; use a new run ID"
            )
        if record is None:
            record = {
                "case_id": case.case_id,
                "app_key": case.app_key,
                "label": label,
                "planned_at": _now(),
                "app_id": None,
            }
            state["records"][case.case_id] = record
            store.save(state)
        elif record.get("app_key") != case.app_key or record.get("label") != label:
            raise LabSafetyError(f"recorded identity changed for case {case.case_id}")

        application: dict[str, Any] | None = None
        effective_case = case
        if record.get("app_id"):
            application = client.get_application(record["app_id"])
        else:
            matches = client.find_applications_by_label(label)
            if len(matches) > 1:
                raise LabSafetyError(f"multiple applications have exact label {label}")
            if matches:
                application = matches[0]
            else:
                if prepare_catalog_settings:
                    effective_case = _prepare_catalog_case(
                        client, store, state, case, record
                    )
                try:
                    application = client.create_application(
                        build_application_payload(effective_case, store.run_id)
                    )
                except Exception:
                    matches = client.find_applications_by_label(label)
                    if len(matches) == 1:
                        application = matches[0]
                    else:
                        raise

        app_id = _validate_application_identity(
            application,
            app_id=record.get("app_id"),
            app_key=case.app_key,
            label=label,
        )
        record["app_id"] = app_id
        record["created_at"] = record.get("created_at") or _now()
        record["observed_status"] = application.get("status")
        state["records"][case.case_id] = record
        store.save(state)
        if application.get("status") != "INACTIVE":
            raise LabSafetyError(
                f"created probe {app_id} is not inactive; stop and review it in Okta"
            )
        _capture_application(
            client,
            store,
            state,
            effective_case,
            record,
            include_metadata=include_metadata,
        )
    return state


def capture_run(
    client: OktaLabClient,
    store: RunStore,
    cases: Sequence[ProbeCase],
    *,
    include_metadata: bool = False,
) -> dict[str, Any]:
    state = store.load()
    cases_by_id = {case.case_id: case for case in cases}
    for case_id, record in state["records"].items():
        if record.get("deleted_at"):
            continue
        case = cases_by_id.get(case_id)
        if case is None or not record.get("app_id"):
            raise LabSafetyError(
                f"cannot capture unrecognized or uncreated case {case_id}"
            )
        _capture_application(
            client,
            store,
            state,
            case,
            record,
            include_metadata=include_metadata,
        )
    return state


def cleanup_run(
    client: OktaLabClient,
    store: RunStore,
    *,
    apply: bool,
) -> dict[str, Any]:
    state = store.load()
    for case_id, record in state["records"].items():
        if record.get("deleted_at"):
            if _reconcile_delayed_cleanup(record):
                store.save(state)
            continue
        app_id = record.get("app_id")
        if not app_id:
            matches = client.find_applications_by_label(record["label"])
            if len(matches) > 1:
                raise LabSafetyError(
                    f"multiple applications have exact label {record['label']}"
                )
            if not matches:
                record["absent_at"] = _now()
                _reconcile_delayed_cleanup(record)
                store.save(state)
                continue
            application = matches[0]
            app_id = _validate_application_identity(
                application,
                app_id=None,
                app_key=record["app_key"],
                label=record["label"],
            )
            record["app_id"] = app_id
            store.save(state)
        else:
            try:
                application = client.get_application(app_id)
            except OktaNotFound:
                record["absent_at"] = _now()
                _reconcile_delayed_cleanup(record)
                store.save(state)
                continue
            _validate_application_identity(
                application,
                app_id=app_id,
                app_key=record["app_key"],
                label=record["label"],
            )

        if application.get("status") != "INACTIVE":
            raise LabSafetyError(
                f"refusing to delete {app_id}: expected INACTIVE status, got "
                f"{application.get('status')!r}"
            )
        record["cleanup_verified_at"] = _now()
        store.save(state)
        if not apply:
            continue
        client.delete_application(app_id)
        try:
            client.get_application(app_id)
        except OktaNotFound:
            record["deleted_at"] = _now()
            _reconcile_delayed_cleanup(record)
            store.save(state)
        else:
            raise LabSafetyError(f"application {app_id} still exists after deletion")
    return state


def _active_trace_cleanup_verified(record: Mapping[str, Any]) -> bool:
    app_clean = bool(record.get("deleted_at") or record.get("absent_at"))
    trace = record.get("active_trace")
    if not isinstance(trace, Mapping):
        return app_clean and trace is None
    user_creation_started = bool(trace.get("user_create_requested_at"))
    user_clean = not user_creation_started or bool(
        trace.get("user_deleted_at") or trace.get("user_absent_at")
    )
    return app_clean and user_clean


def _reconcile_delayed_cleanup(record: dict[str, Any]) -> bool:
    """Mark a stopped attempt clean after a later exact-object verification."""
    attempt = record.get("active_trace_attempt")
    if (
        not isinstance(attempt, Mapping)
        or attempt.get("outcome") != "cleanup_incomplete"
        or not _active_trace_cleanup_verified(record)
    ):
        return False
    recovered_attempt = dict(attempt)
    recovered_attempt.update(
        {
            "outcome": "failed_clean",
            "cleanup_verified": True,
            "cleanup_recovered_at": _now(),
        }
    )
    record["active_trace_attempt"] = recovered_attempt
    return True


def _record_active_trace_attempt(
    store: RunStore,
    case: ProbeCase,
    *,
    started_at: str,
    outcome: str,
    cleanup_verified: bool,
    failure: BaseException | None = None,
    cleanup_failure: BaseException | None = None,
) -> dict[str, Any]:
    state = store.load()
    record = state["records"].get(case.case_id)
    if not isinstance(record, dict):
        raise LabSafetyError("active trace run lost its planned case record")
    attempt: dict[str, Any] = {
        "started_at": started_at,
        "completed_at": _now(),
        "outcome": outcome,
        "cleanup_verified": cleanup_verified,
    }
    if failure is not None:
        attempt["failure_type"] = type(failure).__name__
        failure_category, failure_scope = _active_trace_failure_classification(failure)
        attempt["failure_category"] = failure_category
        attempt["failure_scope"] = failure_scope
        if isinstance(failure, OktaApiError):
            attempt["okta_status_code"] = failure.status_code
            if failure.error_code is not None:
                attempt["okta_error_code"] = failure.error_code
    if cleanup_failure is not None:
        attempt["cleanup_failure_type"] = type(cleanup_failure).__name__
    record["active_trace_attempt"] = attempt
    state["records"][case.case_id] = record
    store.save(state)
    return state


def _active_trace_failure_classification(failure: BaseException) -> tuple[str, str]:
    category_value = getattr(failure, "failure_category", None)
    scope_value = getattr(failure, "failure_scope", None)
    if isinstance(category_value, str) and scope_value in {"case", "campaign"}:
        return category_value, scope_value
    if isinstance(failure, OktaTransportError):
        return "okta_transport", "campaign"
    if isinstance(failure, OktaApiError):
        if failure.status_code == 400:
            return "catalog_configuration_required", "case"
        if failure.status_code == 404:
            return "catalog_integration_unavailable", "case"
        if failure.status_code == 401:
            return "okta_authorization", "campaign"
        if failure.status_code == 403:
            return "catalog_request_rejected", "case"
        if failure.status_code == 429:
            return "okta_rate_limit", "campaign"
        return "okta_api_failure", "campaign"
    if isinstance(failure, LabSafetyError):
        return "safety_invariant", "campaign"
    return "unexpected_failure", "campaign"


def execute_active_trace(
    client: OktaLabClient,
    store: RunStore,
    case: ProbeCase,
    *,
    matrix_sha256: str,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> dict[str, Any]:
    """Create, trace, and clean one app under an outer cleanup boundary."""
    from .active_trace import run_active_trace

    started_at = _now()
    try:
        create_run(
            client,
            store,
            (case,),
            matrix_digest=matrix_sha256,
            max_age_hours=max_age_hours,
            prepare_catalog_settings=True,
        )
        state = run_active_trace(client, store, case)
    except BaseException as failure:
        cleanup_failure: BaseException | None = None
        if store.state_path.exists():
            try:
                cleanup_run(client, store, apply=True)
            except BaseException as error:
                cleanup_failure = error
        cleanup_verified = False
        if store.state_path.exists():
            state = store.load()
            record = state["records"].get(case.case_id)
            cleanup_verified = isinstance(
                record, Mapping
            ) and _active_trace_cleanup_verified(record)
            cleanup_complete = cleanup_verified and cleanup_failure is None
            state = _record_active_trace_attempt(
                store,
                case,
                started_at=started_at,
                outcome=("failed_clean" if cleanup_complete else "cleanup_incomplete"),
                cleanup_verified=cleanup_complete,
                failure=failure,
                cleanup_failure=cleanup_failure,
            )
        if not cleanup_verified or cleanup_failure is not None:
            detail = (
                f"; cleanup also failed with {type(cleanup_failure).__name__}"
                if cleanup_failure is not None
                else ""
            )
            raise LabSafetyError(
                "active trace failed and cleanup is not verified; stop the sweep"
                f"{detail}"
            ) from failure
        attempt = state["records"][case.case_id]["active_trace_attempt"]
        if attempt.get("failure_scope") == "case":
            return state
        raise

    record = state["records"].get(case.case_id)
    cleanup_verified = isinstance(record, Mapping) and _active_trace_cleanup_verified(
        record
    )
    review_path = store.run_dir / "active-review" / f"{case.case_id}.json"
    if not cleanup_verified or not review_path.exists():
        state = _record_active_trace_attempt(
            store,
            case,
            started_at=started_at,
            outcome="cleanup_incomplete",
            cleanup_verified=cleanup_verified,
        )
        raise LabSafetyError(
            "active trace returned without verified cleanup and review evidence; "
            "stop the sweep"
        )
    return _record_active_trace_attempt(
        store,
        case,
        started_at=started_at,
        outcome="captured_clean",
        cleanup_verified=True,
    )


def matrix_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _token_from_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise LabSafetyError(f"required token environment variable is unset: {name}")
    return value


def _confirm_tenant(tenant_url: str, confirmed_host: str | None) -> None:
    actual_host = urlsplit(normalize_tenant_url(tenant_url)).hostname
    if confirmed_host != actual_host:
        raise LabSafetyError(
            f"--confirm-tenant-host must exactly equal {actual_host!r}"
        )


def _print_plan(cases: Sequence[ProbeCase], run_id: str | None) -> None:
    for case in cases:
        label = (
            probe_label(run_id, case)
            if run_id
            else f"{LABEL_PREFIX}<run>-{case.case_id}"
        )
        print(
            json.dumps(
                {
                    "case_id": case.case_id,
                    "app_key": case.app_key,
                    "variant": case.variant,
                    "readiness": case.readiness,
                    "label": label,
                    "settings.app": case.settings_app,
                },
                sort_keys=True,
            )
        )


def _add_matrix_selection(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--case", action="append", default=[], dest="case_ids")
    parser.add_argument("--include-discovery", action="store_true")


def _add_live_connection(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--tenant-url", required=True)
    parser.add_argument("--token-env", default=DEFAULT_TOKEN_ENV)
    parser.add_argument("--state-root", type=Path, default=default_state_root())


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="render the offline probe plan")
    _add_matrix_selection(plan)
    plan.add_argument("--run-id")

    create = subparsers.add_parser("create", help="create inactive temporary apps")
    _add_matrix_selection(create)
    _add_live_connection(create)
    create.add_argument("--run-id", required=True)
    create.add_argument("--include-metadata", action="store_true")
    create.add_argument(
        "--max-age-hours",
        type=int,
        default=DEFAULT_MAX_AGE_HOURS,
        help=f"recorded maximum app age (1-{MAX_ALLOWED_AGE_HOURS}, default 24)",
    )
    create.add_argument("--apply", action="store_true")
    create.add_argument("--confirm-tenant-host")

    active_trace = subparsers.add_parser(
        "active-trace",
        help="activate and trace exactly one app with one ephemeral Okta-only user",
    )
    _add_matrix_selection(active_trace)
    _add_live_connection(active_trace)
    active_trace.add_argument("--run-id", required=True)
    active_trace.add_argument(
        "--max-age-hours",
        type=int,
        default=DEFAULT_MAX_AGE_HOURS,
        help=f"recorded maximum app age (1-{MAX_ALLOWED_AGE_HOURS}, default 24)",
    )
    active_trace.add_argument("--apply", action="store_true")
    active_trace.add_argument("--confirm-tenant-host")
    active_trace.add_argument("--confirm-run-id")

    capture = subparsers.add_parser("capture", help="refresh read-only captures")
    _add_live_connection(capture)
    capture.add_argument("--run-id", required=True)
    capture.add_argument("--include-metadata", action="store_true")

    status = subparsers.add_parser("status", help="show local run state")
    status.add_argument("--tenant-url", required=True)
    status.add_argument("--state-root", type=Path, default=default_state_root())
    status.add_argument("--run-id", required=True)

    active_preflight = subparsers.add_parser(
        "active-preflight",
        help="verify token presence, state isolation, and local browser readiness",
    )
    _add_live_connection(active_preflight)

    sweep_plan = subparsers.add_parser(
        "sweep-plan",
        help="write an offline manifest for sequential one-case active traces",
    )
    _add_matrix_selection(sweep_plan)
    sweep_plan.add_argument("--tenant-url", required=True)
    sweep_plan.add_argument("--state-root", type=Path, default=default_state_root())
    sweep_plan.add_argument("--sweep-id", required=True)
    sweep_plan.add_argument("--details", action="store_true")

    sweep_status = subparsers.add_parser(
        "sweep-status",
        help="summarize an OIN sweep and render its next guarded command",
    )
    sweep_status.add_argument("--tenant-url", required=True)
    sweep_status.add_argument("--state-root", type=Path, default=default_state_root())
    sweep_status.add_argument("--sweep-id", required=True)
    sweep_status.add_argument("--details", action="store_true")

    sweep_audit = subparsers.add_parser(
        "sweep-audit",
        help="read back exact campaign labels and users to detect live residue",
    )
    _add_live_connection(sweep_audit)
    sweep_audit.add_argument("--sweep-id", required=True)
    sweep_audit.add_argument("--details", action="store_true")
    sweep_audit.add_argument(
        "--max-attempts",
        type=int,
        default=4,
        help="bounded attempts per exact read when Okta returns HTTP 429 (default: 4)",
    )

    catalog = subparsers.add_parser(
        "catalog", help="capture a read-only current catalog inventory"
    )
    _add_live_connection(catalog)
    catalog.add_argument("--snapshot-id", required=True)
    catalog.add_argument("--include-non-saml", action="store_true")

    schemas = subparsers.add_parser(
        "schemas", help="capture read-only catalog schemas with resumable checkpoints"
    )
    _add_live_connection(schemas)
    schemas.add_argument("--snapshot-id", required=True)
    schema_targets = schemas.add_mutually_exclusive_group()
    schema_targets.add_argument(
        "--app-key", action="append", default=[], dest="app_keys"
    )
    schema_targets.add_argument(
        "--catalog-snapshot",
        type=Path,
        help="capture every SAML app key from a dated catalog snapshot",
    )
    schemas.add_argument("--resume", action="store_true")
    schemas.add_argument(
        "--max-attempts", type=int, default=DEFAULT_SCHEMA_MAX_ATTEMPTS
    )
    schemas.add_argument(
        "--progress-every", type=int, default=DEFAULT_SCHEMA_PROGRESS_EVERY
    )

    analyze_schemas = subparsers.add_parser(
        "analyze-schemas",
        help="normalize a captured catalog schema snapshot without Okta access",
    )
    analyze_schemas.add_argument("--input", required=True, type=Path)
    analyze_schemas.add_argument("--output", type=Path)

    cleanup = subparsers.add_parser("cleanup", help="verify and delete recorded apps")
    _add_live_connection(cleanup)
    cleanup.add_argument("--run-id", required=True)
    cleanup.add_argument("--apply", action="store_true")
    cleanup.add_argument("--confirm-tenant-host")
    cleanup.add_argument("--confirm-run-id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "active-preflight":
            from .active_trace import active_trace_preflight

            state_root = _external_state_root(args.state_root)
            client = OktaLabClient(
                args.tenant_url,
                _token_from_environment(args.token_env),
            )
            client.find_applications_by_label("oin-lab-preflight-connectivity-check")
            browser_report = active_trace_preflight()
            print(
                json.dumps(
                    {
                        **browser_report,
                        "management_api_read_verified": True,
                        "management_api_requests": 1,
                        "state_root": str(state_root),
                        "tenant_url": client.tenant_url,
                        "token_environment": args.token_env,
                        "token_present": True,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0

        if args.command == "analyze-schemas":
            path = analyze_catalog_schema_file(args.input, args.output)
            analysis = json.loads(path.read_text(encoding="utf-8"))
            print(
                json.dumps(
                    {
                        "application_count": analysis["application_count"],
                        "attribute_count": analysis["attribute_count"],
                        "path": str(path),
                    },
                    sort_keys=True,
                )
            )
            return 0

        if args.command in {"sweep-plan", "sweep-status"}:
            from .sweep import (
                SweepStore,
                compact_sweep_report,
                select_sweep_cases,
                summarize_sweep,
            )

            sweep_store = SweepStore(args.state_root, args.tenant_url, args.sweep_id)
            current_matrix_digest = matrix_digest(args.matrix)
            if args.command == "sweep-plan":
                sweep_cases = select_sweep_cases(
                    load_cases(args.matrix),
                    args.case_ids,
                    include_discovery=args.include_discovery,
                )
                sweep_store.load_or_create(
                    sweep_cases,
                    matrix_path=args.matrix,
                    matrix_sha256=current_matrix_digest,
                    include_discovery=args.include_discovery,
                )
            report = summarize_sweep(
                sweep_store,
                current_matrix_sha256=current_matrix_digest,
            )
            output = report if args.details else compact_sweep_report(report)
            print(json.dumps(output, indent=2, sort_keys=True))
            return 0 if report["safe_to_continue"] else 3

        if args.command == "sweep-audit":
            from .sweep import (
                SweepStore,
                audit_sweep_residue,
                compact_residue_audit,
            )

            sweep_store = SweepStore(args.state_root, args.tenant_url, args.sweep_id)
            client = OktaLabClient(
                args.tenant_url,
                _token_from_environment(args.token_env),
            )
            audit = audit_sweep_residue(
                client,
                sweep_store,
                max_attempts=args.max_attempts,
            )
            output = audit if args.details else compact_residue_audit(audit)
            print(json.dumps(output, indent=2, sort_keys=True))
            return 0 if audit["clean"] else 3

        if args.command == "schemas":
            if not 1 <= args.max_attempts <= MAX_SCHEMA_MAX_ATTEMPTS:
                raise LabSafetyError(
                    f"--max-attempts must be between 1 and {MAX_SCHEMA_MAX_ATTEMPTS}"
                )
            if args.progress_every < 1:
                raise LabSafetyError("--progress-every must be at least 1")

            if args.catalog_snapshot is not None:
                requested_app_keys, source_digest = load_saml_catalog_app_keys(
                    args.catalog_snapshot
                )
                target_source = {
                    "kind": "catalog_snapshot",
                    "sha256": source_digest,
                }
            elif args.app_keys:
                requested_app_keys = tuple(args.app_keys)
                target_source = {
                    "kind": "explicit_app_keys",
                    "sha256": _value_digest(requested_app_keys),
                }
            else:
                requested_app_keys = load_popular_saml_app_keys(args.matrix)
                target_source = {
                    "kind": "matrix_popular_saml",
                    "sha256": matrix_digest(args.matrix),
                }

            invalid_app_keys = sorted(
                app_key
                for app_key in requested_app_keys
                if not _APP_KEY.fullmatch(app_key)
            )
            if invalid_app_keys:
                raise LabSafetyError(
                    "invalid catalog application key(s): " + ", ".join(invalid_app_keys)
                )
            if len(set(requested_app_keys)) != len(requested_app_keys):
                raise LabSafetyError("duplicate catalog application key requested")

            def report_schema_progress(
                processed: int, total: int, captured: int, missing: int
            ) -> None:
                if processed % args.progress_every == 0 or processed == total:
                    print(
                        json.dumps(
                            {
                                "captured": captured,
                                "missing": missing,
                                "processed": processed,
                                "target_count": total,
                            },
                            sort_keys=True,
                        ),
                        file=sys.stderr,
                    )

            client = OktaLabClient(
                args.tenant_url,
                _token_from_environment(args.token_env),
            )
            result = capture_catalog_schemas(
                client,
                CatalogSchemaStore(args.state_root, args.tenant_url, args.snapshot_id),
                requested_app_keys,
                target_source=target_source,
                resume=args.resume,
                max_attempts=args.max_attempts,
                progress=report_schema_progress,
            )
            print(
                json.dumps(
                    {
                        "analysis_path": str(result.analysis_path),
                        "captured_count": result.captured_count,
                        "captured_this_run": result.captured_this_run,
                        "missing_count": result.missing_count,
                        "snapshot_path": str(result.snapshot_path),
                        "target_count": result.target_count,
                    },
                    sort_keys=True,
                )
            )
            return 0

        cases = load_cases(args.matrix)
        if args.command == "plan":
            selected = select_cases(
                cases,
                args.case_ids,
                include_discovery=args.include_discovery,
            )
            _print_plan(selected, args.run_id)
            return 0
        if args.command == "status":
            state = RunStore(args.state_root, args.tenant_url, args.run_id).load()
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0

        if args.command == "catalog":
            client = OktaLabClient(
                args.tenant_url,
                _token_from_environment(args.token_env),
            )
            snapshot = public_catalog_snapshot(
                client.list_catalog_applications(),
                saml_only=not args.include_non_saml,
            )
            path = write_catalog_snapshot(
                args.state_root,
                args.tenant_url,
                args.snapshot_id,
                snapshot,
            )
            print(
                json.dumps(
                    {
                        "application_count": snapshot["application_count"],
                        "path": str(path),
                        "saml_only": snapshot["saml_only"],
                    },
                    sort_keys=True,
                )
            )
            return 0

        store = RunStore(args.state_root, args.tenant_url, args.run_id)
        if args.command in {"create", "active-trace"} and not args.apply:
            selected = select_cases(
                cases,
                args.case_ids,
                include_discovery=args.include_discovery,
            )
            if args.command == "active-trace" and len(selected) != 1:
                raise LabSafetyError("active trace requires exactly one --case")
            _print_plan(selected, args.run_id)
            if args.command == "active-trace":
                print(
                    "dry run only; pass --apply, --confirm-tenant-host, and "
                    "--confirm-run-id to create, trace, and delete one app"
                )
            else:
                print(
                    "dry run only; pass --apply and --confirm-tenant-host to create apps"
                )
            return 0

        if args.command in {"cleanup", "active-trace"} and args.apply:
            if args.confirm_run_id != args.run_id:
                raise LabSafetyError("--confirm-run-id must exactly equal --run-id")
            _confirm_tenant(args.tenant_url, args.confirm_tenant_host)
        elif args.command == "create" and args.apply:
            _confirm_tenant(args.tenant_url, args.confirm_tenant_host)

        client = OktaLabClient(
            args.tenant_url,
            _token_from_environment(args.token_env),
        )
        if args.command == "create":
            selected = select_cases(
                cases,
                args.case_ids,
                include_discovery=args.include_discovery,
            )
            state = create_run(
                client,
                store,
                selected,
                matrix_digest=matrix_digest(args.matrix),
                include_metadata=args.include_metadata,
                max_age_hours=args.max_age_hours,
            )
        elif args.command == "active-trace":
            selected = select_cases(
                cases,
                args.case_ids,
                include_discovery=args.include_discovery,
            )
            if len(selected) != 1:
                raise LabSafetyError("active trace requires exactly one --case")
            state = execute_active_trace(
                client,
                store,
                selected[0],
                matrix_sha256=matrix_digest(args.matrix),
                max_age_hours=args.max_age_hours,
            )
        elif args.command == "capture":
            state = capture_run(
                client,
                store,
                cases,
                include_metadata=args.include_metadata,
            )
        else:
            state = cleanup_run(client, store, apply=args.apply)
            if not args.apply:
                print(
                    "cleanup dry run only; pass --apply, --confirm-tenant-host, "
                    "and --confirm-run-id to delete apps"
                )
        print(json.dumps(state, indent=2, sort_keys=True))
        return 0
    except (
        LabSafetyError,
        MatrixError,
        OktaApiError,
        OktaTransportError,
        SchemaAnalysisError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
