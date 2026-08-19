import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from tools.oin_lab import lab as oin_lab
from tools.oin_lab.lab import (
    CaseScopedLabOutcome,
    CatalogSchemaStore,
    LabSafetyError,
    MATRIX_PATH,
    MatrixError,
    OktaApiError,
    OktaLabClient,
    ProbeCase,
    RunStore,
    REPOSITORY_ROOT,
    _active_trace_failure_classification,
    _synthetic_catalog_value,
    build_application_payload,
    capture_catalog_schemas,
    cleanup_run,
    create_run,
    execute_active_trace,
    load_cases,
    load_popular_saml_app_keys,
    load_saml_catalog_app_keys,
    main,
    matrix_digest,
    normalize_tenant_url,
    public_application_snapshot,
    public_catalog_snapshot,
    select_cases,
    write_catalog_snapshot,
    write_catalog_schema_snapshot,
)


EXPECTED_FAMILIES = {
    "adobecreativecloud",
    "alertmediacom",
    "amazon_aws_sso",
    "asana",
    "atlassian",
    "boxnet",
    "ciscocommonidentity",
    "ciscomeraki",
    "citrixnetscalergateway_saml",
    "cloudconsole",
    "datadog",
    "dialpad",
    "docusign",
    "getpostman",
    "island",
    "island_managementconsole",
    "logicmonitor",
    "logmein",
    "mimecastadmin",
    "mimecastppv3",
    "motus",
    "navan",
    "novatus",
    "odesk",
    "okta_org2org",
    "oraclecloudinfrastructureiam",
    "pagerduty",
    "paloaltonetworkssaml",
    "panw_globalprotect",
    "readcube",
    "salesforce",
    "scim2testapp",
    "sentry",
    "servicenow_ud",
    "sharefile",
    "showpad",
    "simplelegal",
    "slack",
    "tableauonline",
    "vanta",
    "workday",
    "workiva",
    "xmatters",
    "zoomus",
}


class StubResponse:
    def __init__(
        self,
        status_code: int,
        payload: Any = None,
        *,
        text: str | None = None,
        links: dict[str, dict[str, str]] | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else ""
        self.links = links or {}
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._payload, ValueError):
            raise self._payload
        return self._payload


class StubSession:
    def __init__(self, responses: list[StubResponse]):
        self.responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> StubResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


def _case(case_id: str = "slack-workspace") -> ProbeCase:
    return next(case for case in load_cases() if case.case_id == case_id)


def _application(
    *,
    app_id: str = "0oa-oin-lab",
    name: str = "slack",
    label: str = "oin-lab-run1-slack-workspace",
    status: str = "INACTIVE",
) -> dict[str, Any]:
    return {
        "id": app_id,
        "name": name,
        "label": label,
        "status": status,
        "signOnMode": "SAML_2_0",
        "settings": {
            "app": {"domain": "oin-lab-workspace"},
            "signOn": {
                "destination": "https://oin-lab-workspace.slack.com/sso/saml",
                "audience": "https://slack.com",
            },
        },
    }


def _client(session: StubSession) -> OktaLabClient:
    return OktaLabClient(
        "https://lab.okta.test",
        "test-token",
        session=session,  # type: ignore[arg-type]
    )


def _catalog_application_schema(
    app_key: str,
    *,
    required: list[str] | None = None,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": app_key,
        "displayName": app_key.title(),
        "signOnModes": ["SAML_2_0"],
        "_embedded": {
            "schema": {
                "definitions": {
                    "general": {
                        "required": required or [],
                        "properties": properties
                        or {"domain": {"title": "Domain", "type": "string"}},
                    }
                }
            }
        },
    }


def _matrix_query(query: str) -> list[sqlite3.Row]:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    try:
        connection.executescript(MATRIX_PATH.read_text(encoding="utf-8"))
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def test_matrix_covers_baseline_and_popular_families_without_customer_markers():
    cases = load_cases()

    assert len(cases) == 105
    assert EXPECTED_FAMILIES <= {case.app_key for case in cases}
    assert all("redacted" not in case.app_key for case in cases)
    assert all("redacted" not in case.case_id for case in cases)
    assert {case.readiness for case in cases} == {"ready", "discovery", "blocked"}
    aws = next(case for case in cases if case.case_id == "amazon-aws-default")
    assert aws.assignment_profile == {"samlRoles": ["000000000000 -- oin-lab-role"]}
    assert aws.settings_app["awsEnvironmentType"] == "aws.amazon"
    atlassian = next(case for case in cases if case.case_id == "atlassian-jsm")
    assert atlassian.app_link_label_suffix == " Jira Service Management SAML"


def test_popularity_report_entries_and_catalog_mappings_are_complete():
    counts = {
        (row["report_year"], row["cohort"]): row["entry_count"]
        for row in _matrix_query(
            """
            SELECT report_year, cohort, COUNT(*) AS entry_count
            FROM popular_app_report_entries
            GROUP BY report_year, cohort
            """
        )
    }
    unmapped = _matrix_query(
        """
        SELECT DISTINCT entry.report_name
        FROM popular_app_report_entries AS entry
        LEFT JOIN popular_app_catalog_targets AS target
          ON target.report_name = entry.report_name
        WHERE target.target_id IS NULL
        """
    )
    unprobed_saml_targets = _matrix_query(
        """
        SELECT target.target_id
        FROM popular_app_catalog_targets AS target
        LEFT JOIN oin_probe_cases AS probe
          ON probe.app_key = target.app_key
        WHERE target.disposition = 'saml_candidate'
          AND probe.case_id IS NULL
        """
    )
    invalid_absent_targets = _matrix_query(
        """
        SELECT target_id
        FROM popular_app_catalog_targets
        WHERE disposition = 'absent'
          AND (app_key IS NOT NULL OR catalog_display_name IS NOT NULL)
        """
    )

    assert counts == {
        (2024, "most-popular-50"): 50,
        (2025, "growth-callouts"): 7,
        (2025, "overall-top-15"): 15,
        (2026, "fastest-growing-10"): 10,
        (2026, "overall-top-15"): 15,
    }
    assert unmapped == []
    assert unprobed_saml_targets == []
    assert invalid_absent_targets == []
    assert "concur-solutions" in load_popular_saml_app_keys()
    assert "office365" not in load_popular_saml_app_keys()


def test_default_selection_is_limited_to_publicly_documented_ready_cases():
    selected = select_cases(load_cases(), [], include_discovery=False)

    assert len(selected) == 10
    assert all(case.readiness == "ready" for case in selected)
    assert {case.app_key for case in selected} == {
        "panw_globalprotect",
        "salesforce",
        "slack",
        "workday",
        "zoomus",
    }


def test_discovery_and_blocked_cases_require_explicit_handling():
    cases = load_cases()

    with pytest.raises(LabSafetyError, match="--include-discovery"):
        select_cases(cases, ["pagerduty-default"], include_discovery=False)
    assert (
        select_cases(cases, ["pagerduty-default"], include_discovery=True)[0].readiness
        == "discovery"
    )
    with pytest.raises(LabSafetyError, match="blocked probe"):
        select_cases(cases, ["scim2-test-app"], include_discovery=True)


def test_payload_creates_only_an_inactive_catalog_application_body():
    payload = build_application_payload(_case(), "run1")

    assert payload == {
        "name": "slack",
        "label": "oin-lab-run1-slack-workspace",
        "signOnMode": "SAML_2_0",
        "settings": {"app": {"domain": "oin-lab-workspace"}},
    }
    assert "users" not in payload
    assert "groups" not in payload
    assert "credentials" not in payload


@pytest.mark.parametrize(
    "tenant_url",
    [
        "http://lab.okta.test",
        "https://user@lab.okta.test",
        "https://lab.okta.test/admin",
        " https://lab.okta.test",
        "https://lab.okta.test?debug=true",
    ],
)
def test_tenant_url_must_be_an_exact_https_origin(tenant_url: str):
    with pytest.raises(LabSafetyError, match="exact HTTPS origin"):
        normalize_tenant_url(tenant_url)


def test_run_store_refuses_state_inside_the_repository():
    with pytest.raises(LabSafetyError, match="outside the repository workspace"):
        RunStore(REPOSITORY_ROOT / ".tmp" / "oin-lab", "https://lab.okta.test", "run1")


def test_default_state_root_is_allowed_when_workspace_root_is_home(
    monkeypatch: pytest.MonkeyPatch,
):
    home = Path.home().resolve()
    repository = home / "openhound-okta"
    monkeypatch.setattr(oin_lab, "REPOSITORY_WORKSPACE_ROOT", home)
    monkeypatch.setattr(oin_lab, "REPOSITORY_ROOT", repository)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)

    default_root = oin_lab.default_state_root()

    assert oin_lab._external_state_root(default_root) == default_root.resolve()
    with pytest.raises(LabSafetyError, match="outside the repository workspace"):
        oin_lab._external_state_root(repository / ".tmp" / "oin-lab")
    with pytest.raises(LabSafetyError, match="outside the repository workspace"):
        oin_lab._external_state_root(home / "unrelated-state")


def test_load_cases_enforces_active_option_foreign_keys(tmp_path: Path):
    matrix = tmp_path / "matrix.sql"
    matrix.write_text(
        MATRIX_PATH.read_text(encoding="utf-8")
        + "\nINSERT INTO oin_probe_active_options (case_id) "
        + "VALUES ('missing-case');\n",
        encoding="utf-8",
    )

    with pytest.raises(MatrixError, match="FOREIGN KEY constraint failed"):
        load_cases(matrix)


@pytest.mark.parametrize(
    ("attribute", "expected"),
    [
        ({"enum": [None, "first", "second"]}, ("first", "first_catalog_enum")),
        ({"type": "boolean"}, (False, "boolean_false")),
        ({"type": "integer"}, (1, "integer_one")),
        ({"type": "number"}, (1.0, "number_one")),
        (
            {"type": "string", "format": "uri", "name": "siteUrl"},
            (
                "https://oin-lab-34e9aedefffd.invalid/siteurl",
                "reserved_invalid_uri",
            ),
        ),
        (
            {"type": "string", "name": "adminEmail"},
            ("oin-lab-34e9aedefffd@example.invalid", "reserved_invalid_email"),
        ),
        ({"type": "object", "name": "unsupported"}, None),
    ],
)
def test_synthetic_catalog_value_strategies(
    attribute: dict[str, Any], expected: tuple[Any, str] | None
):
    assert _synthetic_catalog_value(attribute, "run1") == expected


def test_client_uses_activate_false_and_does_not_put_token_in_url_or_body():
    session = StubSession([StubResponse(200, _application())])
    client = _client(session)
    payload = build_application_payload(_case(), "run1")

    assert client.create_application(payload)["id"] == "0oa-oin-lab"

    request = session.requests[0]
    assert request["method"] == "POST"
    assert request["url"] == "https://lab.okta.test/api/v1/apps"
    assert request["params"] == {"activate": "false"}
    assert request["json"] == payload
    assert request["headers"]["Authorization"] == "SSWS test-token"
    assert "test-token" not in request["url"]
    assert "test-token" not in str(request["json"])


def test_metadata_request_uses_xml_content_negotiation():
    session = StubSession([StubResponse(200, text="<EntityDescriptor />")])

    assert _client(session).get_saml_metadata("0oa-oin-lab") == ("<EntityDescriptor />")

    request = session.requests[0]
    assert request["headers"]["Accept"] == "application/xml"
    assert "Content-Type" not in request["headers"]


def test_active_trace_client_uses_explicit_user_factor_and_app_lifecycles():
    session = StubSession(
        [
            StubResponse(200, {"id": "00u-test", "status": "ACTIVE"}),
            StubResponse(
                200,
                {
                    "id": "mfa-test",
                    "status": "PENDING_ACTIVATION",
                    "_embedded": {"activation": {"sharedSecret": "base32"}},
                },
            ),
            StubResponse(200, {"id": "mfa-test", "status": "ACTIVE"}),
            StubResponse(200, {}),
            StubResponse(200, {}),
            StubResponse(200, {}),
            StubResponse(204),
        ]
    )
    client = _client(session)

    client.create_user(
        {
            "firstName": "OIN",
            "lastName": "Lab",
            "email": "oin@example.test",
            "login": "oin@example.test",
        },
        "temporary-password",
    )
    client.enroll_totp_factor("00u-test")
    client.activate_factor("00u-test", "mfa-test", "123456")
    client.activate_application("0oa-test")
    client.deactivate_application("0oa-test")
    client.deactivate_user("00u-test")
    client.delete_user("00u-test")

    assert [request["method"] for request in session.requests] == [
        "POST",
        "POST",
        "POST",
        "POST",
        "POST",
        "POST",
        "DELETE",
    ]
    assert session.requests[0]["params"] == {"activate": "true"}
    assert session.requests[1]["json"] == {
        "factorType": "token:software:totp",
        "provider": "GOOGLE",
    }
    assert session.requests[2]["json"] == {"passCode": "123456"}
    assert session.requests[3]["url"].endswith(
        "/api/v1/apps/0oa-test/lifecycle/activate"
    )
    assert session.requests[4]["url"].endswith(
        "/api/v1/apps/0oa-test/lifecycle/deactivate"
    )
    assert session.requests[-1]["url"].endswith("/api/v1/users/00u-test")


def test_application_assignment_includes_only_the_explicit_app_profile():
    session = StubSession([StubResponse(200, {"id": "00u-test", "scope": "USER"})])
    client = _client(session)

    client.assign_application_user(
        "0oa-test",
        "00u-test",
        "oin@example.test",
        profile={"samlRoles": ["000000000000 -- oin-lab-role"]},
    )

    assert session.requests[0]["json"] == {
        "id": "00u-test",
        "scope": "USER",
        "credentials": {"userName": "oin@example.test"},
        "profile": {"samlRoles": ["000000000000 -- oin-lab-role"]},
    }


def test_catalog_inventory_follows_only_same_tenant_pagination():
    session = StubSession(
        [
            StubResponse(
                200,
                [{"name": "first", "signOnModes": ["SAML_2_0"]}],
                links={
                    "next": {
                        "url": (
                            "https://lab.okta.test/api/v1/catalog/apps"
                            "?after=first&limit=200"
                        )
                    }
                },
            ),
            StubResponse(200, [{"name": "second", "signOnModes": []}]),
        ]
    )

    applications = _client(session).list_catalog_applications()

    assert [application["name"] for application in applications] == [
        "first",
        "second",
    ]
    assert session.requests[1]["params"] == {"limit": 200, "after": "first"}


def test_catalog_schema_request_validates_key_and_response_identity():
    session = StubSession(
        [
            StubResponse(
                200,
                {
                    "name": "panw_globalprotect",
                    "displayName": "Palo Alto Networks - GlobalProtect",
                    "_embedded": {"schemas": {"app": {"required": ["baseURL"]}}},
                },
            )
        ]
    )

    application = _client(session).get_catalog_application("panw_globalprotect")

    assert application["name"] == "panw_globalprotect"
    assert session.requests[0]["params"] == {"expand": "schema"}
    with pytest.raises(LabSafetyError, match="invalid catalog application key"):
        _client(StubSession([])).get_catalog_application("invalid/key")


def test_catalog_schema_get_retries_only_retryable_read_failures():
    delays: list[float] = []
    session = StubSession(
        [
            StubResponse(
                429,
                {"errorCode": "E0000047"},
                headers={"X-Rate-Limit-Reset": "105"},
            ),
            StubResponse(503, {"errorCode": "E0000009"}),
            StubResponse(200, _catalog_application_schema("example_app")),
        ]
    )
    client = OktaLabClient(
        "https://lab.okta.test",
        "test-token",
        session=session,  # type: ignore[arg-type]
        sleep=delays.append,
        clock=lambda: 100.0,
    )

    application = client.get_catalog_application("example_app", max_attempts=3)

    assert application["name"] == "example_app"
    assert delays == [5.25, 2.0]
    assert len(session.requests) == 3

    failed_session = StubSession([StubResponse(500, {"errorCode": "failure"})])
    with pytest.raises(OktaApiError):
        OktaLabClient(
            "https://lab.okta.test",
            "test-token",
            session=failed_session,  # type: ignore[arg-type]
            sleep=lambda _: None,
        ).get_catalog_application("example_app", max_attempts=1)
    assert len(failed_session.requests) == 1


def test_catalog_snapshot_selects_sorted_saml_keys(tmp_path: Path):
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            {
                "applications": [
                    {"name": "Apptio", "signOnModes": ["SAML_2_0"]},
                    {"name": "zeta", "signOnModes": ["SAML_2_0"]},
                    {"name": "oidc", "signOnModes": ["OPENID_CONNECT"]},
                    {"name": "alpha", "signOnModes": ["SAML_2_0"]},
                ]
            }
        ),
        encoding="utf-8",
    )

    app_keys, digest = load_saml_catalog_app_keys(path)

    assert app_keys == ("Apptio", "alpha", "zeta")
    assert len(digest) == 64


def test_catalog_schema_capture_checkpoints_resumes_and_materializes(
    tmp_path: Path,
):
    app_keys = ("alpha", "beta", "gamma")
    target_source = {"kind": "test", "sha256": "source-digest"}
    store = CatalogSchemaStore(tmp_path, "https://lab.okta.test", "all-saml-test")
    interrupted_session = StubSession(
        [
            StubResponse(200, _catalog_application_schema("alpha")),
            StubResponse(503, {"errorCode": "temporarily-unavailable"}),
        ]
    )

    with pytest.raises(OktaApiError):
        capture_catalog_schemas(
            _client(interrupted_session),
            store,
            app_keys,
            target_source=target_source,
            resume=False,
            max_attempts=1,
        )

    interrupted_state = store.load()
    assert list(interrupted_state["records"]) == ["alpha"]
    assert (store.raw_directory / "alpha.json").exists()

    resumed_session = StubSession(
        [
            StubResponse(200, _catalog_application_schema("beta")),
            StubResponse(404, {"errorCode": "E0000007"}),
        ]
    )
    result = capture_catalog_schemas(
        _client(resumed_session),
        store,
        app_keys,
        target_source=target_source,
        resume=True,
        max_attempts=1,
    )

    assert [
        request["url"].rsplit("/", 1)[-1] for request in resumed_session.requests
    ] == [
        "beta",
        "gamma",
    ]
    assert result.target_count == 3
    assert result.captured_count == 2
    assert result.missing_count == 1
    assert result.captured_this_run == 1
    snapshot = json_from(result.snapshot_path)
    assert [application["name"] for application in snapshot["applications"]] == [
        "alpha",
        "beta",
    ]
    assert snapshot["missing_applications"] == [
        {"app_key": "gamma", "status_code": 404}
    ]
    assert json_from(result.analysis_path)["application_count"] == 2
    assert all(
        path.stat().st_mode & 0o777 == 0o600
        for path in (
            store.state_path,
            store.raw_directory / "alpha.json",
            store.raw_directory / "beta.json",
            result.snapshot_path,
            result.analysis_path,
        )
    )

    stable_snapshot = result.snapshot_path.read_text(encoding="utf-8")
    recovered_state = store.load()
    recovered_state["records"].pop("alpha")
    store.save(recovered_state)
    no_requests = StubSession([])
    repeated = capture_catalog_schemas(
        _client(no_requests),
        store,
        app_keys,
        target_source=target_source,
        resume=True,
        max_attempts=1,
    )
    assert repeated.captured_this_run == 0
    assert no_requests.requests == []
    assert repeated.snapshot_path.read_text(encoding="utf-8") == stable_snapshot


def test_schema_capture_refuses_implicit_or_changed_resume(tmp_path: Path):
    store = CatalogSchemaStore(tmp_path, "https://lab.okta.test", "resume-test")
    app_keys = ("alpha",)
    target_source = {"kind": "test", "sha256": "one"}
    store.load_or_create(app_keys, target_source=target_source, resume=False)

    with pytest.raises(LabSafetyError, match="pass --resume"):
        store.load_or_create(app_keys, target_source=target_source, resume=False)
    with pytest.raises(LabSafetyError, match="targets changed"):
        store.load_or_create(
            app_keys,
            target_source={"kind": "test", "sha256": "two"},
            resume=True,
        )


def test_catalog_snapshot_filters_saml_and_stays_outside_repository(tmp_path: Path):
    snapshot = public_catalog_snapshot(
        [
            {
                "name": "saml-app",
                "displayName": "SAML App",
                "status": "ACTIVE",
                "signOnModes": ["SAML_2_0"],
                "features": ["IMPORT_NEW_USERS"],
            },
            {
                "name": "oidc-app",
                "displayName": "OIDC App",
                "status": "ACTIVE",
                "signOnModes": ["OPENID_CONNECT"],
            },
        ],
        saml_only=True,
    )

    path = write_catalog_snapshot(
        tmp_path,
        "https://lab.okta.test",
        "20260814",
        snapshot,
    )

    assert snapshot["application_count"] == 1
    assert snapshot["applications"][0]["name"] == "saml-app"
    assert json_from(path)["application_count"] == 1
    assert path.stat().st_mode & 0o777 == 0o600

    schema_path = write_catalog_schema_snapshot(
        tmp_path,
        "https://lab.okta.test",
        "20260814",
        [{"name": "saml-app", "_embedded": {"schemas": {}}}],
    )
    assert json_from(schema_path)["application_count"] == 1
    assert schema_path.stat().st_mode & 0o777 == 0o600


def test_public_snapshot_keeps_route_fields_but_omits_credentials_and_links():
    application = _application()
    application["settings"]["app"]["apiToken"] = "secret-value"
    application["settings"]["signOn"]["signingCertificate"] = "certificate"
    application["credentials"] = {"signing": {"kid": "private"}}
    application["_links"] = {"self": {"href": "tenant-specific"}}
    application["settings"]["signOn"]["idpIssuer"] = (
        "https://lab.okta.test/app/slack/0oa-oin-lab/sso/saml"
    )

    snapshot = public_application_snapshot(
        _case(),
        application,
        tenant_url="https://lab.okta.test",
        app_id="0oa-oin-lab",
        label="oin-lab-run1-slack-workspace",
    )

    serialized = str(snapshot)
    assert "secret-value" not in serialized
    assert "certificate" not in serialized
    assert "credentials" not in snapshot["application"]
    assert "_links" not in snapshot["application"]
    assert snapshot["application"]["settings"]["signOn"]["destination"] == (
        "https://oin-lab-workspace.slack.com/sso/saml"
    )
    assert snapshot["application"]["settings"]["signOn"]["idpIssuer"] == (
        "https://{oktaDomain}/app/slack/{appId}/sso/saml"
    )


def test_create_run_persists_identity_and_both_raw_and_review_captures(tmp_path: Path):
    application = _application()
    session = StubSession(
        [
            StubResponse(200, []),
            StubResponse(200, application),
            StubResponse(200, application),
        ]
    )
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")

    state = create_run(
        _client(session),
        store,
        [_case()],
        matrix_digest=matrix_digest(MATRIX_PATH),
    )

    record = state["records"]["slack-workspace"]
    assert record["app_id"] == "0oa-oin-lab"
    assert record["observed_status"] == "INACTIVE"
    assert state["expires_at"]
    assert (store.run_dir / "raw" / "slack-workspace.json").exists()
    review_path = store.run_dir / "review" / "slack-workspace.json"
    assert review_path.exists()
    assert json_from(review_path)["requires_human_review"] is True
    assert store.state_path.stat().st_mode & 0o777 == 0o600
    assert review_path.stat().st_mode & 0o777 == 0o600


def test_active_create_prepares_missing_nonroute_catalog_settings(tmp_path: Path):
    application = _application()
    session = StubSession(
        [
            StubResponse(200, []),
            StubResponse(
                200,
                _catalog_application_schema(
                    "slack",
                    required=["subdomain"],
                    properties={"subdomain": {"type": "string"}},
                ),
            ),
            StubResponse(200, application),
            StubResponse(200, application),
        ]
    )
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")

    state = create_run(
        _client(session),
        store,
        [_case()],
        matrix_digest=matrix_digest(MATRIX_PATH),
        prepare_catalog_settings=True,
    )

    payload = session.requests[2]["json"]
    assert payload["settings"]["app"]["subdomain"].startswith("oin-lab-")
    preparation = state["records"]["slack-workspace"]["catalog_schema_preparation"]
    assert preparation["synthesized_fields"] == [
        {
            "name": "subdomain",
            "section": "general",
            "strategy": "deterministic_lab_slug",
        }
    ]
    assert payload["settings"]["app"]["subdomain"] not in str(preparation)


def test_active_create_stops_before_create_for_required_sensitive_setting(
    tmp_path: Path,
):
    session = StubSession(
        [
            StubResponse(200, []),
            StubResponse(
                200,
                _catalog_application_schema(
                    "slack",
                    required=["apiToken"],
                    properties={"apiToken": {"type": "string"}},
                ),
            ),
        ]
    )
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")

    with pytest.raises(CaseScopedLabOutcome) as raised:
        create_run(
            _client(session),
            store,
            [_case()],
            matrix_digest=matrix_digest(MATRIX_PATH),
            prepare_catalog_settings=True,
        )

    assert raised.value.failure_category == "unsupported_required_catalog_input"
    assert [request["method"] for request in session.requests] == ["GET", "GET"]
    preparation = store.load()["records"]["slack-workspace"][
        "catalog_schema_preparation"
    ]
    assert preparation["unresolved_required_fields"] == ["apiToken"]


def test_active_trace_skips_required_explicit_route_without_stopping_campaign(
    tmp_path: Path,
):
    case = _case("amazon-aws-sso-default")
    store = RunStore(tmp_path, "https://lab.okta.test", "campaign1-005")
    session = StubSession(
        [
            StubResponse(200, []),
            StubResponse(
                200,
                _catalog_application_schema(
                    case.app_key,
                    required=["acsURL", "entityID"],
                    properties={
                        "acsURL": {"type": "string", "format": "uri"},
                        "entityID": {"type": "string", "format": "uri"},
                    },
                ),
            ),
            StubResponse(200, []),
        ]
    )

    state = execute_active_trace(
        _client(session),
        store,
        case,
        matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    record = state["records"][case.case_id]
    assert record["absent_at"]
    assert record["catalog_schema_preparation"]["required_explicit_route_fields"] == [
        "acsURL",
        "entityID",
    ]
    attempt = record["active_trace_attempt"]
    assert attempt["outcome"] == "failed_clean"
    assert attempt["cleanup_verified"] is True
    assert attempt["failure_type"] == "CaseScopedLabOutcome"
    assert attempt["failure_category"] == "required_explicit_route_input"
    assert attempt["failure_scope"] == "case"
    assert [request["method"] for request in session.requests] == ["GET", "GET", "GET"]


def test_create_run_records_unavailable_metadata_without_activating_app(
    tmp_path: Path,
):
    application = _application()
    session = StubSession(
        [
            StubResponse(200, []),
            StubResponse(200, application),
            StubResponse(200, application),
            StubResponse(404, {"errorCode": "E0000007"}),
        ]
    )
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")

    state = create_run(
        _client(session),
        store,
        [_case()],
        matrix_digest=matrix_digest(MATRIX_PATH),
        include_metadata=True,
    )

    record = state["records"]["slack-workspace"]
    assert record["saml_metadata_status"] == "unavailable"
    assert record["observed_status"] == "INACTIVE"
    assert "metadata.xml" not in {path.name for path in store.run_dir.rglob("*")}


def test_create_run_stops_if_okta_does_not_leave_the_app_inactive(tmp_path: Path):
    application = _application(status="ACTIVE")
    session = StubSession(
        [
            StubResponse(200, []),
            StubResponse(200, application),
        ]
    )
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")

    with pytest.raises(LabSafetyError, match="is not inactive"):
        create_run(
            _client(session),
            store,
            [_case()],
            matrix_digest=matrix_digest(MATRIX_PATH),
        )

    state = store.load()
    assert state["records"]["slack-workspace"]["observed_status"] == "ACTIVE"
    assert [request["method"] for request in session.requests] == ["GET", "POST"]


def test_create_run_refuses_an_expired_run_before_any_network_request(tmp_path: Path):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["expires_at"] = "2020-01-01T00:00:00+00:00"
    store.save(state)
    session = StubSession([])

    with pytest.raises(LabSafetyError, match="exceeded its maximum app age"):
        create_run(
            _client(session),
            store,
            [_case()],
            matrix_digest=matrix_digest(MATRIX_PATH),
        )

    assert session.requests == []


@pytest.mark.parametrize("hours", [0, 169])
def test_run_store_bounds_the_maximum_app_age(tmp_path: Path, hours: int):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")

    with pytest.raises(LabSafetyError, match="max app age"):
        store.load_or_create(matrix_digest(MATRIX_PATH), max_age_hours=hours)


def test_cleanup_deletes_only_exact_inactive_recorded_app_and_verifies_absence(
    tmp_path: Path,
):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"]["slack-workspace"] = {
        "case_id": "slack-workspace",
        "app_key": "slack",
        "label": "oin-lab-run1-slack-workspace",
        "app_id": "0oa-oin-lab",
    }
    store.save(state)
    session = StubSession(
        [
            StubResponse(200, _application()),
            StubResponse(204),
            StubResponse(404, {"errorCode": "E0000007"}),
        ]
    )

    cleaned = cleanup_run(_client(session), store, apply=True)

    assert cleaned["records"]["slack-workspace"]["deleted_at"]
    assert [request["method"] for request in session.requests] == [
        "GET",
        "DELETE",
        "GET",
    ]


def test_cleanup_refuses_active_or_identity_mismatched_apps(tmp_path: Path):
    for application, expected in (
        (_application(status="ACTIVE"), "expected INACTIVE"),
        (_application(label="unrelated-app"), "does not match"),
    ):
        store = RunStore(
            tmp_path / expected.replace(" ", "-"),
            "https://lab.okta.test",
            "run1",
        )
        state = store.load_or_create(matrix_digest(MATRIX_PATH))
        state["records"]["slack-workspace"] = {
            "case_id": "slack-workspace",
            "app_key": "slack",
            "label": "oin-lab-run1-slack-workspace",
            "app_id": "0oa-oin-lab",
        }
        store.save(state)
        session = StubSession([StubResponse(200, application)])

        with pytest.raises(LabSafetyError, match=expected):
            cleanup_run(_client(session), store, apply=True)
        assert [request["method"] for request in session.requests] == ["GET"]


def test_cleanup_reconciles_a_stopped_attempt_after_verified_absence(tmp_path: Path):
    store = RunStore(tmp_path, "https://lab.okta.test", "campaign1-001")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"]["slack-workspace"] = {
        "case_id": "slack-workspace",
        "app_key": "slack",
        "label": "oin-lab-campaign1-001-slack-workspace",
        "app_id": None,
        "active_trace_attempt": {
            "outcome": "cleanup_incomplete",
            "cleanup_verified": False,
            "failure_type": "OktaTransportError",
            "cleanup_failure_type": "OktaTransportError",
        },
    }
    store.save(state)
    session = StubSession([StubResponse(200, [])])

    cleaned = cleanup_run(_client(session), store, apply=True)

    record = cleaned["records"]["slack-workspace"]
    assert record["absent_at"]
    assert record["active_trace_attempt"]["outcome"] == "failed_clean"
    assert record["active_trace_attempt"]["cleanup_verified"] is True
    assert record["active_trace_attempt"]["cleanup_recovered_at"]


def test_active_trace_outer_boundary_cleans_app_after_pretrace_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    case = _case()
    store = RunStore(tmp_path, "https://lab.okta.test", "campaign1-001")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case.case_id] = {
        "case_id": case.case_id,
        "app_key": case.app_key,
        "label": "oin-lab-campaign1-001-slack-workspace",
        "app_id": "0oa-oin-lab",
    }
    store.save(state)
    session = StubSession(
        [
            StubResponse(
                200,
                _application(label="oin-lab-campaign1-001-slack-workspace"),
            ),
            StubResponse(204),
            StubResponse(404, {"errorCode": "E0000007"}),
        ]
    )

    def fail_before_trace(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("synthetic initial capture failure")

    monkeypatch.setattr("tools.oin_lab.lab.create_run", fail_before_trace)

    with pytest.raises(RuntimeError, match="synthetic initial capture failure"):
        execute_active_trace(
            _client(session),
            store,
            case,
            matrix_sha256=matrix_digest(MATRIX_PATH),
        )

    record = store.load()["records"][case.case_id]
    assert record["deleted_at"]
    assert record["active_trace_attempt"]["outcome"] == "failed_clean"
    assert record["active_trace_attempt"]["cleanup_verified"] is True
    assert record["active_trace_attempt"]["failure_scope"] == "campaign"


def test_active_trace_refuses_reused_state_without_cleaning_sibling_case(
    tmp_path: Path,
):
    case = _case()
    store = RunStore(tmp_path, "https://lab.okta.test", "campaign1-001")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"]["asana-default"] = {
        "case_id": "asana-default",
        "app_key": "asana",
        "label": "oin-lab-campaign1-001-asana-default",
        "app_id": "0oa-sibling",
    }
    store.save(state)
    session = StubSession([])

    with pytest.raises(LabSafetyError, match="another probe case"):
        execute_active_trace(
            _client(session),
            store,
            case,
            matrix_sha256=matrix_digest(MATRIX_PATH),
        )

    assert session.requests == []
    assert "deleted_at" not in store.load()["records"]["asana-default"]


def test_run_store_reports_corrupt_json_and_missing_matrix_digest(tmp_path: Path):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state.pop("matrix_sha256")
    store.save(state)

    with pytest.raises(LabSafetyError, match="invalid or mismatched run state"):
        store.load_or_create(matrix_digest(MATRIX_PATH))

    store.state_path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(LabSafetyError, match="unable to read run state"):
        store.load()


def test_active_trace_returns_clean_case_specific_no_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    from tools.oin_lab.active_trace import TraceNoCaptureError

    case = _case()
    store = RunStore(tmp_path, "https://lab.okta.test", "campaign1-001")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case.case_id] = {
        "case_id": case.case_id,
        "app_key": case.app_key,
        "label": "oin-lab-campaign1-001-slack-workspace",
        "app_id": "0oa-oin-lab",
    }
    store.save(state)
    session = StubSession(
        [
            StubResponse(
                200,
                _application(label="oin-lab-campaign1-001-slack-workspace"),
            ),
            StubResponse(204),
            StubResponse(404, {"errorCode": "E0000007"}),
        ]
    )

    monkeypatch.setattr("tools.oin_lab.lab.create_run", lambda *_args, **_kwargs: None)

    def no_capture(*_args: Any, **_kwargs: Any) -> None:
        raise TraceNoCaptureError(
            "outbound_saml_response_missing", "synthetic no capture"
        )

    monkeypatch.setattr("tools.oin_lab.active_trace.run_active_trace", no_capture)

    result = execute_active_trace(
        _client(session),
        store,
        case,
        matrix_sha256=matrix_digest(MATRIX_PATH),
    )

    attempt = result["records"][case.case_id]["active_trace_attempt"]
    assert attempt["outcome"] == "failed_clean"
    assert attempt["cleanup_verified"] is True
    assert attempt["failure_category"] == "outbound_saml_response_missing"
    assert attempt["failure_scope"] == "case"


@pytest.mark.parametrize(
    ("status_code", "expected"),
    [
        (401, ("okta_authorization", "campaign")),
        (403, ("catalog_request_rejected", "case")),
        (429, ("okta_rate_limit", "campaign")),
    ],
)
def test_active_trace_classifies_okta_status_without_treating_every_403_as_auth(
    status_code: int,
    expected: tuple[str, str],
):
    response = StubResponse(
        status_code,
        {
            "errorCode": "E0000006",
            "errorSummary": "synthetic rejected request",
        },
    )
    error = OktaApiError("POST", "/api/v1/apps", response)  # type: ignore[arg-type]

    assert _active_trace_failure_classification(error) == expected


def test_active_trace_outer_boundary_stops_on_unverified_user_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    case = _case()
    store = RunStore(tmp_path, "https://lab.okta.test", "campaign1-001")
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"][case.case_id] = {
        "case_id": case.case_id,
        "app_key": case.app_key,
        "label": "oin-lab-campaign1-001-slack-workspace",
        "app_id": "0oa-oin-lab",
        "deleted_at": "2026-08-15T00:00:00+00:00",
        "active_trace": {
            "user_create_requested_at": "2026-08-15T00:00:00+00:00",
            "user_id": "00u-test",
        },
    }
    store.save(state)

    def fail_before_trace(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("synthetic trace failure")

    monkeypatch.setattr("tools.oin_lab.lab.create_run", fail_before_trace)

    with pytest.raises(LabSafetyError, match="cleanup is not verified"):
        execute_active_trace(
            _client(StubSession([])),
            store,
            case,
            matrix_sha256=matrix_digest(MATRIX_PATH),
        )

    attempt = store.load()["records"][case.case_id]["active_trace_attempt"]
    assert attempt["outcome"] == "cleanup_incomplete"
    assert attempt["cleanup_verified"] is False


def test_create_cli_is_offline_without_apply(monkeypatch, capsys, tmp_path: Path):
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)

    result = main(
        [
            "create",
            "--tenant-url",
            "https://lab.okta.test",
            "--state-root",
            str(tmp_path),
            "--run-id",
            "run1",
            "--case",
            "slack-workspace",
        ]
    )

    assert result == 0
    assert "dry run only" in capsys.readouterr().out
    assert not list(tmp_path.rglob("*"))


def test_active_preflight_verifies_api_read_and_does_not_expose_token(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
):
    monkeypatch.setenv("OIN_TEST_TOKEN", "private-test-token")
    monkeypatch.setattr(
        "tools.oin_lab.active_trace.active_trace_preflight",
        lambda: {
            "browser": "chromium",
            "browser_launch_verified": True,
            "network_requests": 0,
        },
    )
    requests: list[str] = []

    def verify_api_read(_client: OktaLabClient, label: str) -> list[dict[str, Any]]:
        requests.append(label)
        return []

    monkeypatch.setattr(OktaLabClient, "find_applications_by_label", verify_api_read)

    result = main(
        [
            "active-preflight",
            "--tenant-url",
            "https://lab.okta.test",
            "--state-root",
            str(tmp_path),
            "--token-env",
            "OIN_TEST_TOKEN",
        ]
    )

    assert result == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["browser_launch_verified"] is True
    assert report["network_requests"] == 0
    assert report["management_api_read_verified"] is True
    assert report["management_api_requests"] == 1
    assert report["token_environment"] == "OIN_TEST_TOKEN"
    assert requests == ["oin-lab-preflight-connectivity-check"]
    assert "private-test-token" not in output


def test_active_preflight_rejects_repository_state_before_api_read(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    monkeypatch.setenv("OIN_TEST_TOKEN", "private-test-token")

    def unexpected_api_read(
        _client: OktaLabClient, _label: str
    ) -> list[dict[str, Any]]:
        raise AssertionError("API read must not precede state-root validation")

    monkeypatch.setattr(
        OktaLabClient, "find_applications_by_label", unexpected_api_read
    )

    result = main(
        [
            "active-preflight",
            "--tenant-url",
            "https://lab.okta.test",
            "--state-root",
            str(REPOSITORY_ROOT / ".tmp"),
            "--token-env",
            "OIN_TEST_TOKEN",
        ]
    )

    assert result == 2
    output = capsys.readouterr()
    assert "outside the repository workspace" in output.err
    assert "private-test-token" not in output.err


def test_schema_cli_uses_catalog_snapshot_without_loading_matrix(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
):
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(
        json.dumps(
            {
                "applications": [
                    {"name": "zeta", "signOnModes": ["SAML_2_0"]},
                    {"name": "oidc", "signOnModes": ["OPENID_CONNECT"]},
                    {"name": "alpha", "signOnModes": ["SAML_2_0"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    session = StubSession(
        [
            StubResponse(200, _catalog_application_schema("alpha")),
            StubResponse(200, _catalog_application_schema("zeta")),
        ]
    )
    client = _client(session)
    monkeypatch.setenv("OKTA_API_TOKEN", "unused-test-token")
    monkeypatch.setattr(
        "tools.oin_lab.lab.OktaLabClient", lambda *_args, **_kwargs: client
    )

    result = main(
        [
            "--matrix",
            str(tmp_path / "does-not-exist.sql"),
            "schemas",
            "--tenant-url",
            "https://lab.okta.test",
            "--state-root",
            str(tmp_path / "state"),
            "--snapshot-id",
            "all-saml-cli",
            "--catalog-snapshot",
            str(catalog_path),
            "--progress-every",
            "1",
        ]
    )

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["target_count"] == 2
    assert output["captured_count"] == 2
    assert output["missing_count"] == 0
    assert [request["url"].rsplit("/", 1)[-1] for request in session.requests] == [
        "alpha",
        "zeta",
    ]


def json_from(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
