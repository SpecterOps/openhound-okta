import base64
from dataclasses import replace
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest
import requests

from tools.oin_lab.active_trace import (
    ApplicationLink,
    BrowserTraceInput,
    TraceNoCaptureError,
    _application_links,
    _playwright_navigation_outcome,
    _redact_trace_diagnostic,
    _select_application_link,
    _totp_code,
    ephemeral_user_login,
    observe_external_saml_request,
    public_trace_observation,
    run_active_trace,
)
from tools.oin_lab.lab import (
    LabSafetyError,
    OktaNotFound,
    RunStore,
    load_cases,
    matrix_digest,
    MATRIX_PATH,
)


def _not_found(method: str, path: str) -> OktaNotFound:
    response = requests.Response()
    response.status_code = 404
    response._content = b'{"errorCode":"E0000007"}'
    return OktaNotFound(method, path, response)


class FakeActiveClient:
    def __init__(
        self,
        *,
        app_features: list[str] | None = None,
        app_links: tuple[dict[str, Any], ...] | None = None,
    ):
        self.application: dict[str, Any] | None = {
            "id": "0oa-oin-lab",
            "name": "slack",
            "label": "oin-lab-run1-slack-workspace",
            "status": "INACTIVE",
            "signOnMode": "SAML_2_0",
            "features": app_features or [],
        }
        self.user: dict[str, Any] | None = None
        self.assigned = False
        self.assignment_profile: dict[str, Any] | None = None
        self.events: list[str] = []
        self.app_links = app_links

    def get_application(self, app_id: str) -> dict[str, Any]:
        if self.application is None:
            raise _not_found("GET", f"/api/v1/apps/{app_id}")
        return dict(self.application)

    def list_application_users(self, app_id: str) -> tuple[dict[str, Any], ...]:
        if self.assigned and self.user is not None:
            return ({"id": self.user["id"], "scope": "USER"},)
        return ()

    def get_user(self, user_id_or_login: str) -> dict[str, Any]:
        if self.user is None:
            raise _not_found("GET", f"/api/v1/users/{user_id_or_login}")
        if user_id_or_login not in {self.user["id"], self.user["profile"]["login"]}:
            raise _not_found("GET", f"/api/v1/users/{user_id_or_login}")
        return dict(self.user)

    def create_user(self, profile: dict[str, Any], password: str) -> dict[str, Any]:
        assert password
        self.events.append("create_user")
        self.user = {
            "id": "00u-oin-lab",
            "status": "ACTIVE",
            "profile": dict(profile),
        }
        return dict(self.user)

    def list_user_roles(self, user_id: str) -> tuple[dict[str, Any], ...]:
        return ()

    def list_user_groups(self, user_id: str) -> tuple[dict[str, Any], ...]:
        return (
            {
                "id": "00g-everyone",
                "type": "BUILT_IN",
                "profile": {"name": "Everyone"},
            },
        )

    def list_group_applications(self, group_id: str) -> tuple[dict[str, Any], ...]:
        return ()

    def list_user_app_links(self, user_id: str) -> tuple[dict[str, Any], ...]:
        if not self.assigned:
            return ()
        if self.app_links is not None:
            return self.app_links
        return (
            {
                "appInstanceId": "0oa-oin-lab",
                "linkUrl": "https://lab.okta.test/home/slack/0oa-oin-lab/1",
            },
        )

    def enroll_totp_factor(self, user_id: str) -> dict[str, Any]:
        self.events.append("enroll_totp")
        return {
            "id": "mfa-oin-lab",
            "status": "PENDING_ACTIVATION",
            "_embedded": {"activation": {"sharedSecret": "JBSWY3DPEHPK3PXP"}},
        }

    def activate_factor(
        self, user_id: str, factor_id: str, pass_code: str
    ) -> dict[str, Any]:
        self.events.append("activate_totp")
        assert factor_id == "mfa-oin-lab"
        assert len(pass_code) == 6 and pass_code.isdigit()
        return {"id": factor_id, "status": "ACTIVE"}

    def activate_application(self, app_id: str) -> None:
        self.events.append("activate_app")
        assert self.application is not None
        self.application["status"] = "ACTIVE"

    def assign_application_user(
        self,
        app_id: str,
        user_id: str,
        login: str,
        *,
        profile: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.events.append("assign_user")
        self.assigned = True
        self.assignment_profile = profile
        return {"id": user_id, "scope": "USER"}

    def unassign_application_user(self, app_id: str, user_id: str) -> None:
        self.events.append("unassign_user")
        self.assigned = False

    def deactivate_user(self, user_id: str) -> None:
        self.events.append("deactivate_user")
        assert self.user is not None
        self.user["status"] = "DEPROVISIONED"

    def delete_user(self, user_id: str) -> None:
        self.events.append("delete_user")
        self.user = None

    def deactivate_application(self, app_id: str) -> None:
        self.events.append("deactivate_app")
        assert self.application is not None
        self.application["status"] = "INACTIVE"

    def delete_application(self, app_id: str) -> None:
        self.events.append("delete_app")
        self.application = None


def _state(store: RunStore) -> None:
    state = store.load_or_create(matrix_digest(MATRIX_PATH))
    state["records"]["slack-workspace"] = {
        "case_id": "slack-workspace",
        "app_key": "slack",
        "label": "oin-lab-run1-slack-workspace",
        "app_id": "0oa-oin-lab",
    }
    store.save(state)


def _response_observation() -> dict[str, Any]:
    response = b"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      Destination="https://workspace.slack.com/sso/saml">
      <saml:Issuer>http://www.okta.com/exk1234567890ABCDE</saml:Issuer>
      <saml:Assertion><saml:Conditions><saml:AudienceRestriction>
      <saml:Audience>https://slack.com</saml:Audience>
      </saml:AudienceRestriction></saml:Conditions></saml:Assertion>
    </samlp:Response>"""
    return observe_external_saml_request(
        "https://workspace.slack.com/sso/saml?tenant=synthetic",
        "POST",
        urlencode(
            {"SAMLResponse": base64.b64encode(response).decode(), "RelayState": "x"}
        ),
    )


def test_external_saml_observation_extracts_routes_without_assertion_contents():
    observation = _response_observation()

    assert observation["saml_parameter"] == "SAMLResponse"
    assert observation["saml"]["message_type"] == "Response"
    assert observation["saml"]["destinations_and_recipients"] == [
        "https://workspace.slack.com/sso/saml"
    ]
    assert observation["saml"]["audiences"] == ["https://slack.com"]
    assert '"x"' not in json.dumps(observation)
    assert "Assertion" not in json.dumps(observation)

    public = public_trace_observation(observation)
    assert public["request_url"] == (
        "https://workspace.slack.com/sso/saml?tenant=%7Bvalue%7D"
    )
    assert public["saml"]["issuers"] == ["http://www.okta.com/{oktaObjectId}"]
    assert public["requires_human_review"] is True


def test_active_trace_uses_exactly_one_ephemeral_user_and_deletes_both_objects(
    tmp_path: Path,
):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient()
    seen_input: BrowserTraceInput | None = None

    def trace(trace_input: BrowserTraceInput) -> dict[str, Any]:
        nonlocal seen_input
        seen_input = trace_input
        return _response_observation()

    case = next(case for case in load_cases() if case.case_id == "slack-workspace")
    state = run_active_trace(
        client,  # type: ignore[arg-type]
        store,
        case,
        browser_tracer=trace,
    )

    assert seen_input is not None
    assert seen_input.login == "oin-lab-run1-user@lab.okta.test"
    assert seen_input.password
    assert client.user is None
    assert client.application is None
    assert client.events == [
        "create_user",
        "enroll_totp",
        "activate_totp",
        "activate_app",
        "assign_user",
        "unassign_user",
        "deactivate_user",
        "delete_user",
        "deactivate_app",
        "delete_app",
    ]
    record = state["records"]["slack-workspace"]
    assert record["deleted_at"]
    serialized_state = store.state_path.read_text(encoding="utf-8")
    assert seen_input.password not in serialized_state
    assert seen_input.totp_secret not in serialized_state
    assert seen_input.login not in serialized_state
    assert (store.run_dir / "active-raw" / "slack-workspace.json").exists()
    assert (store.run_dir / "active-review" / "slack-workspace.json").exists()


def test_application_links_wait_for_stable_multi_link_propagation():
    responses = iter(
        (
            (),
            (
                {
                    "appInstanceId": "0oa-oin-lab",
                    "label": "Primary",
                    "linkUrl": "https://lab.okta.test/home/app/primary",
                },
            ),
            (
                {
                    "appInstanceId": "0oa-oin-lab",
                    "label": "Primary",
                    "linkUrl": "https://lab.okta.test/home/app/primary",
                },
                {
                    "appInstanceId": "0oa-oin-lab",
                    "label": "Secondary",
                    "linkUrl": "https://lab.okta.test/home/app/secondary",
                },
            ),
            (
                {
                    "appInstanceId": "0oa-oin-lab",
                    "label": "Primary",
                    "linkUrl": "https://lab.okta.test/home/app/primary",
                },
                {
                    "appInstanceId": "0oa-oin-lab",
                    "label": "Secondary",
                    "linkUrl": "https://lab.okta.test/home/app/secondary",
                },
            ),
        )
    )

    class PropagatingClient:
        def list_user_app_links(self, _user_id: str) -> tuple[dict[str, Any], ...]:
            return next(responses)

    waits: list[float] = []
    links = _application_links(
        PropagatingClient(),  # type: ignore[arg-type]
        "00u-oin-lab",
        "0oa-oin-lab",
        "https://lab.okta.test",
        attempts=4,
        delay_seconds=0.25,
        sleep=waits.append,
    )

    assert [link.label for link in links] == ["Primary", "Secondary"]
    assert waits == [0.25, 0.25, 0.25]


def test_application_links_refuse_a_link_for_another_app():
    class UnexpectedLinkClient:
        def list_user_app_links(self, _user_id: str) -> tuple[dict[str, Any], ...]:
            return (
                {
                    "appInstanceId": "0oa-unexpected",
                    "linkUrl": "https://lab.okta.test/home/app/unexpected",
                },
            )

    with pytest.raises(LabSafetyError, match="unexpected application link"):
        _application_links(
            UnexpectedLinkClient(),  # type: ignore[arg-type]
            "00u-oin-lab",
            "0oa-oin-lab",
            "https://lab.okta.test",
            attempts=1,
            sleep=lambda _: None,
        )


def test_application_links_bound_an_empty_propagation_wait():
    class EmptyLinkClient:
        def list_user_app_links(self, _user_id: str) -> tuple[dict[str, Any], ...]:
            return ()

    waits: list[float] = []
    with pytest.raises(LabSafetyError, match="bounded propagation wait"):
        _application_links(
            EmptyLinkClient(),  # type: ignore[arg-type]
            "00u-oin-lab",
            "0oa-oin-lab",
            "https://lab.okta.test",
            attempts=3,
            delay_seconds=0.25,
            sleep=waits.append,
        )

    assert waits == [0.25, 0.25]


def test_application_link_variant_selection_uses_dynamic_label_suffix():
    links = (
        ApplicationLink(
            url="https://lab.okta.test/home/app/primary",
            label="oin-lab-run1-atlassian-jira Jira SAML",
        ),
        ApplicationLink(
            url="https://lab.okta.test/home/app/secondary",
            label="oin-lab-run1-atlassian-jira Confluence SAML",
        ),
    )

    selected, index = _select_application_link(
        links,
        probe_app_label="oin-lab-run1-atlassian-jira",
        label_suffix=" Confluence SAML",
    )

    assert selected.url.endswith("/secondary")
    assert index == 2


def test_application_link_variant_selection_fails_cleanly_when_missing():
    links = (
        ApplicationLink(
            url="https://lab.okta.test/home/app/primary",
            label="oin-lab-run1-atlassian-jira Jira SAML",
        ),
    )

    with pytest.raises(TraceNoCaptureError) as raised:
        _select_application_link(
            links,
            probe_app_label="oin-lab-run1-atlassian-jira",
            label_suffix=" Confluence SAML",
        )

    assert raised.value.failure_category == "app_link_variant_unavailable"
    assert raised.value.failure_scope == "case"


def test_active_trace_records_multi_link_selection_without_failing(tmp_path: Path):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient(
        app_links=(
            {
                "appInstanceId": "0oa-oin-lab",
                "label": "Primary",
                "linkUrl": "https://lab.okta.test/home/app/primary",
            },
            {
                "appInstanceId": "0oa-oin-lab",
                "label": "Secondary",
                "linkUrl": "https://lab.okta.test/home/app/secondary",
            },
        )
    )
    case = next(case for case in load_cases() if case.case_id == "slack-workspace")
    selected_urls: list[str] = []

    def trace(trace_input: BrowserTraceInput) -> dict[str, Any]:
        selected_urls.append(trace_input.app_link_url)
        return _response_observation()

    state = run_active_trace(
        client,  # type: ignore[arg-type]
        store,
        case,
        browser_tracer=trace,
    )

    selection = state["records"][case.case_id]["active_trace"]["app_link_selection"]
    assert selection == {
        "available_count": 2,
        "available_labels": ["Primary", "Secondary"],
        "selected_index": 1,
        "selected_label": "Primary",
    }
    assert selected_urls == ["https://lab.okta.test/home/app/primary"]
    review = json.loads(
        (store.run_dir / "active-review" / "slack-workspace.json").read_text()
    )
    assert review["app_link_selection"] == selection


def test_active_trace_passes_matrix_assignment_profile(tmp_path: Path):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient()
    case = replace(
        next(case for case in load_cases() if case.case_id == "slack-workspace"),
        assignment_profile={"samlRoles": ["000000000000 -- oin-lab-role"]},
    )

    state = run_active_trace(
        client,  # type: ignore[arg-type]
        store,
        case,
        browser_tracer=lambda _: _response_observation(),
    )

    assert client.assignment_profile == {"samlRoles": ["000000000000 -- oin-lab-role"]}
    assert state["records"][case.case_id]["active_trace"][
        "assignment_profile_fields"
    ] == ["samlRoles"]


def test_active_trace_refuses_provisioning_features_before_creating_user(
    tmp_path: Path,
):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient(app_features=["PUSH_NEW_USERS"])
    case = next(case for case in load_cases() if case.case_id == "slack-workspace")

    with pytest.raises(LabSafetyError, match="provisioning or import"):
        run_active_trace(
            client,  # type: ignore[arg-type]
            store,
            case,
            browser_tracer=lambda _: {},
        )

    assert client.events == []
    assert client.user is None


def test_active_trace_cleans_up_when_browser_capture_fails(tmp_path: Path):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient()
    case = next(case for case in load_cases() if case.case_id == "slack-workspace")

    def fail_browser(_: BrowserTraceInput) -> dict[str, Any]:
        raise RuntimeError("synthetic browser failure")

    with pytest.raises(RuntimeError, match="synthetic browser failure"):
        run_active_trace(
            client,  # type: ignore[arg-type]
            store,
            case,
            browser_tracer=fail_browser,
        )

    assert client.user is None
    assert client.application is None
    assert client.assigned is False
    assert store.load()["records"]["slack-workspace"]["deleted_at"]


def test_playwright_dns_failure_is_a_clean_case_outcome():
    error = RuntimeError(
        "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://synthetic.invalid"
    )

    with pytest.raises(TraceNoCaptureError) as raised:
        _playwright_navigation_outcome(error, None)

    assert raised.value.failure_category == "downstream_navigation_failed"
    assert raised.value.failure_scope == "case"


def test_playwright_runtime_failure_remains_campaign_scoped():
    error = RuntimeError("Target page, context or browser has been closed")

    with pytest.raises(RuntimeError, match="browser has been closed"):
        _playwright_navigation_outcome(error, None)


def test_playwright_dns_failure_with_okta_app_link_is_a_clean_case_outcome():
    error = RuntimeError(
        "Page.goto: net::ERR_NAME_NOT_RESOLVED at https://lab.okta.test/app"
    )

    with pytest.raises(TraceNoCaptureError) as raised:
        _playwright_navigation_outcome(error, None)

    assert raised.value.failure_category == "downstream_navigation_failed"
    assert raised.value.failure_scope == "case"


def test_playwright_error_after_capture_returns_the_capture():
    capture = _response_observation()

    assert _playwright_navigation_outcome(
        RuntimeError("net::ERR_ABORTED"), capture
    ) == (capture)


def test_trace_diagnostics_redact_ephemeral_login_from_nested_fields():
    login = "oin-lab-run1-user@lab.okta.test"
    diagnostic = {
        "current_url": f"https://lab.okta.test/{login}",
        "input_fields": [{"name": login, "autocomplete": "username"}],
        "submit_controls": [{"text": f"Continue {login}", "value": login}],
    }

    redacted = _redact_trace_diagnostic(diagnostic, login)
    serialized = json.dumps(redacted)

    assert login not in serialized
    assert serialized.count("{ephemeralLogin}") == 4


def test_user_absence_state_save_failure_does_not_interrupt_app_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient()
    case = next(case for case in load_cases() if case.case_id == "slack-workspace")
    original_save = store.save
    save_failed = False

    def fail_user_absence_save(state: dict[str, Any]) -> None:
        nonlocal save_failed
        trace = state["records"][case.case_id].get("active_trace", {})
        if trace.get("user_absent_at") and not save_failed:
            save_failed = True
            raise OSError("synthetic state save failure")
        original_save(state)

    def fail_user_creation(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("synthetic user creation failure")

    monkeypatch.setattr(store, "save", fail_user_absence_save)
    monkeypatch.setattr(client, "create_user", fail_user_creation)

    with pytest.raises(LabSafetyError, match="user absence state save") as raised:
        run_active_trace(client, store, case)  # type: ignore[arg-type]

    assert isinstance(raised.value.__cause__, RuntimeError)
    assert client.application is None


def test_active_trace_rejects_non_saml_browser_navigation_and_cleans_up(
    tmp_path: Path,
):
    store = RunStore(tmp_path, "https://lab.okta.test", "run1")
    _state(store)
    client = FakeActiveClient()
    case = next(case for case in load_cases() if case.case_id == "slack-workspace")

    with pytest.raises(LabSafetyError, match="outbound SAMLResponse"):
        run_active_trace(
            client,  # type: ignore[arg-type]
            store,
            case,
            browser_tracer=lambda _: {
                "schema_version": 1,
                "request_url": "https://login.okta.com/discovery/iframe.html",
                "request_method": "GET",
                "parameter_names": [],
            },
        )

    assert client.user is None
    assert client.application is None
    assert not (store.run_dir / "active-raw" / "slack-workspace.json").exists()


def test_ephemeral_login_is_tenant_and_run_scoped():
    assert ephemeral_user_login("https://preview.oktapreview.com", "refresh-1") == (
        "oin-lab-refresh-1-user@preview.oktapreview.com"
    )


def test_totp_matches_rfc_6238_sha1_vector():
    assert _totp_code("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", at=59) == "287082"
