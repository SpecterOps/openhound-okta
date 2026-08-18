"""Guarded active-app tracing for ephemeral Okta OIN research.

This module is intentionally separate from the inactive catalog harness. An active
trace creates one temporary Okta-only user, assigns exactly that user to exactly one
recorded OIN lab app, blocks the outbound SAML request in the browser, and removes
both objects before returning.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from typing import Any
from unicodedata import category
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
import zlib

from defusedxml import ElementTree  # type: ignore[import-untyped]

from .lab import (
    CaseScopedLabOutcome,
    LabSafetyError,
    OktaLabClient,
    OktaNotFound,
    ProbeCase,
    RunStore,
    _now,
    _validate_application_identity,
)


_ALLOWED_APP_FEATURES = {"AUTO_UPDATE_USERNAME"}
_SAML_PARAMETER_NAMES = {"SAMLRequest", "SAMLResponse", "RelayState"}
_OKTA_OBJECT_ID = re.compile(r"\b(?:0oa|exk)[A-Za-z0-9]{10,}\b")
_CASE_SCOPED_NAVIGATION_ERRORS = (
    "net::err_aborted",
    "net::err_address_unreachable",
    "net::err_connection_refused",
    "net::err_connection_timed_out",
    "net::err_invalid_url",
    "net::err_name_not_resolved",
    "net::err_unknown_url_scheme",
)


@dataclass(frozen=True)
class BrowserTraceInput:
    tenant_url: str
    app_link_url: str
    login: str
    password: str
    totp_secret: str
    totp_activation_counter: int


@dataclass(frozen=True)
class TotpEnrollment:
    shared_secret: str
    activation_counter: int


BrowserTracer = Callable[[BrowserTraceInput], Mapping[str, Any]]


class TraceNoCaptureError(CaseScopedLabOutcome):
    """A case-specific trace outcome that is safe to continue after cleanup."""

    def __init__(self, category: str, message: str):
        super().__init__(category, message)


@dataclass(frozen=True)
class ApplicationLink:
    url: str
    label: str | None


def _playwright_navigation_outcome(
    error: BaseException,
    captured: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    if captured is not None:
        return captured
    normalized = str(error).casefold()
    if any(marker in normalized for marker in _CASE_SCOPED_NAVIGATION_ERRORS):
        raise TraceNoCaptureError(
            "downstream_navigation_failed",
            "browser navigation failed before an outbound SAMLResponse was captured",
        ) from error
    raise error


def active_trace_preflight() -> dict[str, Any]:
    """Verify the optional browser runtime locally without contacting Okta."""
    try:
        from playwright.sync_api import Error as PlaywrightError  # type: ignore[import-not-found]
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError as error:  # pragma: no cover - optional live dependency
        raise LabSafetyError(
            "Playwright is required for active OIN traces; install the oin-lab "
            "development dependency and browser"
        ) from error

    try:
        with sync_playwright() as playwright:
            executable_path = playwright.chromium.executable_path
            browser = playwright.chromium.launch(headless=True)
            try:
                browser_version = browser.version
            finally:
                browser.close()
    except PlaywrightError as error:
        raise LabSafetyError(
            "Playwright Chromium is not installed or cannot launch"
        ) from error
    return {
        "browser": "chromium",
        "browser_executable": executable_path,
        "browser_version": browser_version,
        "browser_launch_verified": True,
        "network_requests": 0,
    }


def ephemeral_user_login(tenant_url: str, run_id: str) -> str:
    host = urlsplit(tenant_url).hostname
    if not host:
        raise LabSafetyError("tenant URL has no hostname")
    login = f"oin-lab-{run_id}-user@{host}"
    if len(login) > 100 or any(
        character.isspace() or category(character).startswith("C")
        for character in login
    ):
        raise LabSafetyError("ephemeral user login is invalid")
    return login


def _random_password() -> str:
    # The credential exists only in memory for the duration of one trace.
    return f"{secrets.token_urlsafe(24)}aA1!"


def _totp_code(shared_secret: str, *, at: float | None = None) -> str:
    try:
        key = base64.b32decode(shared_secret.upper(), casefold=True)
    except (binascii.Error, ValueError) as error:
        raise LabSafetyError("Okta returned an invalid TOTP shared secret") from error
    counter = int(time.time() if at is None else at) // 30
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def _enroll_ephemeral_totp(client: OktaLabClient, user_id: str) -> TotpEnrollment:
    factor = client.enroll_totp_factor(user_id)
    factor_id = factor.get("id")
    embedded = factor.get("_embedded")
    activation = embedded.get("activation") if isinstance(embedded, Mapping) else None
    shared_secret = (
        activation.get("sharedSecret") if isinstance(activation, Mapping) else None
    )
    if not isinstance(factor_id, str) or not isinstance(shared_secret, str):
        raise LabSafetyError("Okta did not return TOTP activation material")
    activation_time = time.time()
    activation_counter = int(activation_time) // 30
    activated = client.activate_factor(
        user_id, factor_id, _totp_code(shared_secret, at=activation_time)
    )
    if activated.get("id") != factor_id or activated.get("status") != "ACTIVE":
        raise LabSafetyError("ephemeral TOTP factor did not become ACTIVE")
    return TotpEnrollment(shared_secret, activation_counter)


def _require_traceable_application(application: Mapping[str, Any]) -> None:
    if application.get("status") != "INACTIVE":
        raise LabSafetyError("active trace requires a recorded INACTIVE application")
    if application.get("signOnMode") != "SAML_2_0":
        raise LabSafetyError("active trace requires a SAML_2_0 application")
    features = application.get("features", [])
    if not isinstance(features, list) or not all(
        isinstance(feature, str) for feature in features
    ):
        raise LabSafetyError("application features are malformed")
    unexpected = sorted(set(features) - _ALLOWED_APP_FEATURES)
    if unexpected:
        raise LabSafetyError(
            "refusing active trace because application features may enable "
            f"provisioning or import: {', '.join(unexpected)}"
        )


def _require_isolated_user(client: OktaLabClient, user: Mapping[str, Any]) -> str:
    user_id = user.get("id")
    if not isinstance(user_id, str) or user.get("status") != "ACTIVE":
        raise LabSafetyError("ephemeral OIN user is not ACTIVE")
    if client.list_user_roles(user_id):
        raise LabSafetyError("ephemeral OIN user unexpectedly has an admin role")
    groups = client.list_user_groups(user_id)
    if len(groups) != 1:
        raise LabSafetyError("ephemeral OIN user inherited an unexpected group")
    group = groups[0]
    profile = group.get("profile")
    if (
        group.get("type") != "BUILT_IN"
        or not isinstance(profile, Mapping)
        or profile.get("name") != "Everyone"
        or not isinstance(group.get("id"), str)
    ):
        raise LabSafetyError("ephemeral OIN user is not isolated to built-in Everyone")
    if client.list_group_applications(group["id"]):
        raise LabSafetyError("built-in Everyone grants applications to the test user")
    if client.list_user_app_links(user_id):
        raise LabSafetyError("ephemeral OIN user already has an application link")
    return user_id


def _wait_for_active_user(
    client: OktaLabClient, user_id: str, *, attempts: int = 10
) -> dict[str, Any]:
    for attempt in range(attempts):
        user = client.get_user(user_id)
        if user.get("status") == "ACTIVE":
            return user
        if attempt + 1 < attempts:
            time.sleep(0.5)
    raise LabSafetyError("ephemeral OIN user did not become ACTIVE")


def _safe_application_link_label(link: Mapping[str, Any]) -> str | None:
    for key in ("label", "appName"):
        value = link.get(key)
        if (
            isinstance(value, str)
            and value
            and len(value) <= 200
            and not any(category(character).startswith("C") for character in value)
        ):
            return value
    return None


def _application_links(
    client: OktaLabClient,
    user_id: str,
    app_id: str,
    tenant_url: str,
    *,
    attempts: int = 30,
    delay_seconds: float = 0.5,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[ApplicationLink, ...]:
    """Wait for the exact app's links and require one stable readback."""
    previous_fingerprint: tuple[tuple[str, str], ...] | None = None
    last_links: tuple[ApplicationLink, ...] | None = None
    for attempt in range(attempts):
        raw_links = client.list_user_app_links(user_id)
        if any(link.get("appInstanceId") != app_id for link in raw_links):
            raise LabSafetyError(
                "ephemeral OIN user received an unexpected application link"
            )
        if len(raw_links) > 25:
            raise LabSafetyError("OIN app exposed an unexpected number of app links")

        links: list[ApplicationLink] = []
        seen_urls: set[str] = set()
        for raw_link in raw_links:
            link_url = raw_link.get("linkUrl")
            if not isinstance(link_url, str) or link_url in seen_urls:
                raise LabSafetyError("OIN app returned a malformed or duplicate link")
            parsed = urlsplit(link_url)
            if urlunsplit((parsed.scheme, parsed.netloc, "", "", "")) != tenant_url:
                raise LabSafetyError("OIN app link left the confirmed Okta tenant")
            seen_urls.add(link_url)
            links.append(
                ApplicationLink(
                    url=link_url,
                    label=_safe_application_link_label(raw_link),
                )
            )

        current = tuple(links)
        fingerprint = tuple(sorted((link.url, link.label or "") for link in current))
        if current and fingerprint == previous_fingerprint:
            return current
        if current:
            previous_fingerprint = fingerprint
            last_links = current
        if attempt + 1 < attempts:
            sleep(delay_seconds)

    if last_links:
        return last_links
    raise TraceNoCaptureError(
        "app_link_unavailable",
        "assigned user received no OIN app link after the bounded propagation wait",
    )


def _select_application_link(
    links: tuple[ApplicationLink, ...],
    *,
    probe_app_label: str,
    label_suffix: str | None,
) -> tuple[ApplicationLink, int]:
    """Select the matrix-pinned product link without relying on link ordering."""
    if label_suffix is None:
        return links[0], 1

    expected_label = f"{probe_app_label}{label_suffix}"
    matches = [
        (index, link)
        for index, link in enumerate(links, start=1)
        if link.label == expected_label
    ]
    if len(matches) != 1:
        raise TraceNoCaptureError(
            "app_link_variant_unavailable",
            "the requested OIN app-link variant was not exposed by the catalog app",
        )
    return matches[0][1], matches[0][0]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _decode_saml_message(value: str, parameter: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise LabSafetyError(f"captured {parameter} is not valid base64") from error
    if parameter == "SAMLRequest" and not decoded.lstrip().startswith(b"<"):
        try:
            decoded = zlib.decompress(decoded, -zlib.MAX_WBITS)
        except zlib.error as error:
            raise LabSafetyError(
                "captured SAMLRequest is not XML or DEFLATE"
            ) from error
    return decoded


def _saml_route_fields(message: bytes) -> dict[str, Any]:
    try:
        root = ElementTree.fromstring(message)
    except ElementTree.ParseError as error:
        raise LabSafetyError("captured SAML message is not valid XML") from error

    destinations = sorted(
        {
            value
            for element in root.iter()
            for key, value in element.attrib.items()
            if _local_name(key)
            in {"Destination", "Recipient", "AssertionConsumerServiceURL"}
            and value
        }
    )
    audiences = sorted(
        {
            (element.text or "").strip()
            for element in root.iter()
            if _local_name(element.tag) == "Audience" and (element.text or "").strip()
        }
    )
    issuers = sorted(
        {
            (element.text or "").strip()
            for element in root.iter()
            if _local_name(element.tag) == "Issuer" and (element.text or "").strip()
        }
    )
    return {
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "message_type": _local_name(root.tag),
        "destinations_and_recipients": destinations,
        "audiences": audiences,
        "issuers": issuers,
    }


def observe_external_saml_request(
    url: str, method: str, post_data: str | None
) -> dict[str, Any]:
    parsed = urlsplit(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    form = parse_qs(post_data or "", keep_blank_values=True)
    parameters = {**query, **form}
    present = sorted(name for name in _SAML_PARAMETER_NAMES if name in parameters)
    observation: dict[str, Any] = {
        "schema_version": 1,
        "request_url": url,
        "request_method": method,
        "parameter_names": present,
    }
    for parameter in ("SAMLResponse", "SAMLRequest"):
        values = parameters.get(parameter, [])
        if len(values) > 1:
            raise LabSafetyError(f"captured request has multiple {parameter} values")
        if values:
            observation["saml_parameter"] = parameter
            observation["saml"] = _saml_route_fields(
                _decode_saml_message(values[0], parameter)
            )
            break
    return observation


def public_trace_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    request_url = observation.get("request_url")
    if not isinstance(request_url, str):
        raise LabSafetyError("trace observation has no request URL")
    parsed = urlsplit(request_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    sanitized_query = urlencode(
        [(key, "{value}") for key in sorted(query) if key not in _SAML_PARAMETER_NAMES]
    )
    saml = observation.get("saml")
    public_saml: dict[str, Any] | None = None
    if isinstance(saml, Mapping):
        public_saml = {
            key: (
                [
                    _OKTA_OBJECT_ID.sub("{oktaObjectId}", value)
                    for value in saml.get(key, [])
                    if isinstance(value, str)
                ]
                if key in {"destinations_and_recipients", "audiences", "issuers"}
                else saml.get(key)
            )
            for key in (
                "message_sha256",
                "message_type",
                "destinations_and_recipients",
                "audiences",
                "issuers",
            )
            if key in saml
        }
    return {
        "schema_version": observation.get("schema_version"),
        "request_url": urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, sanitized_query, "")
        ),
        "request_method": observation.get("request_method"),
        "parameter_names": observation.get("parameter_names"),
        "saml_parameter": observation.get("saml_parameter"),
        "saml": public_saml,
        "requires_human_review": True,
    }


def _require_saml_response_observation(
    observation: Mapping[str, Any], tenant_url: str
) -> None:
    request_url = observation.get("request_url")
    if not isinstance(request_url, str):
        raise LabSafetyError("browser trace did not return a request URL")
    parsed = urlsplit(request_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or urlunsplit((parsed.scheme, parsed.netloc, "", "", "")) == tenant_url
    ):
        raise TraceNoCaptureError(
            "outbound_saml_response_missing",
            "browser trace did not leave Okta over HTTPS",
        )
    if observation.get("saml_parameter") != "SAMLResponse" or not isinstance(
        observation.get("saml"), Mapping
    ):
        raise TraceNoCaptureError(
            "outbound_saml_response_missing",
            "browser trace did not capture an outbound SAMLResponse",
        )


def capture_with_playwright(trace_input: BrowserTraceInput) -> Mapping[str, Any]:
    try:
        from playwright.sync_api import Error as PlaywrightError  # type: ignore[import-not-found]
        from playwright.sync_api import sync_playwright  # type: ignore[import-not-found]
    except ImportError as error:  # pragma: no cover - optional live dependency
        raise LabSafetyError(
            "Playwright is required for active OIN traces; install the oin-lab "
            "development dependency and browser"
        ) from error

    tenant_host = urlsplit(trace_input.tenant_url).hostname
    captured: dict[str, Any] | None = None

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context()

        def route_request(route: Any, request: Any) -> None:
            nonlocal captured
            parsed = urlsplit(request.url)
            carries_saml = (
                "SAMLRequest" in request.url
                or "SAMLResponse" in request.url
                or "SAMLRequest" in (request.post_data or "")
                or "SAMLResponse" in (request.post_data or "")
            )
            if parsed.hostname == tenant_host:
                route.continue_()
                return
            if (
                not carries_saml
                and parsed.hostname == "login.okta.com"
                and parsed.path == "/discovery/iframe.html"
                and request.method == "GET"
            ):
                route.continue_()
                return
            if (
                not carries_saml
                and parsed.hostname
                and parsed.hostname.endswith(".oktacdn.com")
                and request.method == "GET"
                and not request.is_navigation_request()
            ):
                route.continue_()
                return
            if captured is None and carries_saml:
                captured = observe_external_saml_request(
                    request.url, request.method, request.post_data
                )
            route.abort()

        context.route("**/*", route_request)
        page = context.new_page()
        try:
            try:
                page.goto(trace_input.app_link_url, wait_until="domcontentloaded")
            except PlaywrightError as error:
                return _playwright_navigation_outcome(error, captured)

            terminal_markers = (
                "not assigned to this application",
                "not assigned to the application",
                "you don't have access to this app",
                "you do not have access to this app",
                "account or password is incorrect",
                "incorrect password",
                "unable to sign in",
            )
            totp_attempted = False
            selected_totp = False
            for _ in range(12):
                if captured is not None:
                    return captured
                try:
                    body_text = page.locator("body").inner_text().casefold()
                    if any(marker in body_text for marker in terminal_markers):
                        raise LabSafetyError(
                            "Okta rejected the ephemeral OIN browser authentication"
                        )

                    google_authenticator = page.locator(
                        '[data-se="google_otp"] a[data-se="button"], '
                        'a[aria-label="Select Google Authenticator."]'
                    ).first
                    if (
                        google_authenticator.count()
                        and google_authenticator.is_visible()
                    ):
                        google_authenticator.click()
                        selected_totp = True
                        page.wait_for_timeout(1_500)
                        continue

                    back_to_sign_in = page.locator(
                        'a:has-text("Back to sign in"), '
                        'button:has-text("Back to sign in")'
                    ).first
                    if (
                        back_to_sign_in.count()
                        and back_to_sign_in.is_visible()
                        and (
                            "verification email" in body_text
                            or "send me an email" in body_text
                        )
                    ):
                        back_to_sign_in.click()
                        page.wait_for_timeout(1_500)
                        continue

                    password_authenticator = page.locator(
                        'button:has-text("Password"), a:has-text("Password"), '
                        'input[type="submit"][value*="Password"]'
                    ).first
                    if (
                        password_authenticator.count()
                        and password_authenticator.is_visible()
                    ):
                        password_authenticator.click()
                        page.wait_for_timeout(1_500)
                        continue

                    identifier = page.locator(
                        'input[name="identifier"], input[name="username"], '
                        'input[type="email"], input[autocomplete="username"], '
                        "#okta-signin-username"
                    ).first
                    if identifier.count() and identifier.is_visible():
                        identifier.fill(trace_input.login)
                        identifier.press("Enter")
                        page.wait_for_timeout(2_000)
                        continue

                    password = page.locator(
                        'input[type="password"], input[name="password"], '
                        'input[name="credentials.passcode"][type="password"], '
                        "#okta-signin-password"
                    ).first
                    if password.count() and password.is_visible():
                        password.fill(trace_input.password)
                        try:
                            password.press("Enter")
                        except PlaywrightError:
                            if captured is None:
                                raise
                        page.wait_for_timeout(2_000)
                        continue

                    otp = page.locator(
                        'input[name="answer"], input[type="tel"], '
                        'input[name="credentials.passcode"]:not([type="password"]), '
                        'input[autocomplete="one-time-code"]'
                    ).first
                    if otp.count() and otp.is_visible():
                        if (
                            not selected_totp
                            and "google authenticator" not in body_text
                        ):
                            raise LabSafetyError(
                                "ephemeral OIN user received a non-TOTP MFA challenge"
                            )
                        if totp_attempted:
                            raise LabSafetyError(
                                "Okta rejected the ephemeral OIN TOTP code"
                            )
                        if (
                            int(time.time()) // 30
                            <= trace_input.totp_activation_counter
                        ):
                            next_window = (trace_input.totp_activation_counter + 1) * 30
                            wait_ms = max(
                                0, int((next_window - time.time() + 0.5) * 1_000)
                            )
                            page.wait_for_timeout(wait_ms)
                        otp.fill(_totp_code(trace_input.totp_secret))
                        totp_attempted = True
                        try:
                            otp.press("Enter")
                        except PlaywrightError:
                            if captured is None:
                                raise
                        page.wait_for_timeout(2_000)
                        continue
                    page.wait_for_timeout(1_000)
                except PlaywrightError as error:
                    return _playwright_navigation_outcome(error, captured)
            input_fields = page.locator("input").evaluate_all(
                """elements => elements.map(element => ({
                    name: element.getAttribute('name'),
                    type: element.getAttribute('type'),
                    autocomplete: element.getAttribute('autocomplete')
                }))"""
            )
            current = urlsplit(page.url)
            current_url = urlunsplit(
                (current.scheme, current.netloc, current.path, "", "")
            )
            alerts = [
                text.replace(trace_input.login, "{ephemeralLogin}")
                for text in page.locator(
                    '[role="alert"], .o-form-error-container, .okta-form-infobox-error'
                ).all_inner_texts()
                if text.strip()
            ]
            visible_text = " ".join(page.locator("body").inner_text().split())
            visible_text = visible_text.replace(trace_input.login, "{ephemeralLogin}")[
                :1_000
            ]
            submit_controls = page.locator(
                'button, input[type="submit"], input[type="button"], '
                'a:has-text("Select")'
            ).evaluate_all(
                """elements => elements.map(element => ({
                    tag: element.tagName,
                    text: (element.innerText || '').trim(),
                    value: element.getAttribute('value'),
                    classes: element.getAttribute('class'),
                    dataSe: element.getAttribute('data-se')
                }))"""
            )
            raise TraceNoCaptureError(
                "outbound_saml_response_missing",
                "browser did not observe an outbound SAML request; "
                f"current_url={current_url!r}, input_fields={input_fields!r}, "
                f"alerts={alerts!r}, submit_controls={submit_controls!r}, "
                f"visible_text={visible_text!r}",
            )
        finally:
            context.close()
            browser.close()


def _delete_ephemeral_user(client: OktaLabClient, user_id: str, login: str) -> None:
    try:
        user = client.get_user(user_id)
    except OktaNotFound:
        return
    profile = user.get("profile")
    if not isinstance(profile, Mapping) or profile.get("login") != login:
        raise LabSafetyError("refusing cleanup because ephemeral user identity changed")
    if user.get("status") != "DEPROVISIONED":
        client.deactivate_user(user_id)
    client.delete_user(user_id)
    try:
        client.get_user(user_id)
    except OktaNotFound:
        return
    raise LabSafetyError("ephemeral OIN user still exists after deletion")


def run_active_trace(
    client: OktaLabClient,
    store: RunStore,
    case: ProbeCase,
    *,
    browser_tracer: BrowserTracer = capture_with_playwright,
) -> dict[str, Any]:
    """Trace one app with one ephemeral user, then remove both live objects."""
    state = store.load()
    if set(state["records"]) != {case.case_id}:
        raise LabSafetyError("active trace run must contain exactly one probe case")
    record = state["records"][case.case_id]
    app_id = record.get("app_id")
    if not isinstance(app_id, str):
        raise LabSafetyError("active trace requires a recorded application ID")
    login = ephemeral_user_login(store.tenant_url, store.run_id)
    password = _random_password()
    user_id: str | None = None
    user_creation_attempted = False
    safe_to_cleanup_app = False
    original_error: BaseException | None = None
    cleanup_errors: list[str] = []
    try:
        application = client.get_application(app_id)
        _validate_application_identity(
            application, app_id=app_id, app_key=case.app_key, label=record["label"]
        )
        _require_traceable_application(application)
        if client.list_application_users(app_id):
            raise LabSafetyError(
                "active trace application already has a user assignment"
            )
        safe_to_cleanup_app = True
        record["active_trace"] = {
            "login_sha256": hashlib.sha256(login.encode()).hexdigest(),
            "started_at": _now(),
        }
        store.save(state)

        try:
            client.get_user(login)
        except OktaNotFound:
            pass
        else:
            raise LabSafetyError("ephemeral OIN user login already exists")

        user_creation_attempted = True
        record["active_trace"]["user_create_requested_at"] = _now()
        store.save(state)
        user = client.create_user(
            {
                "firstName": "OIN",
                "lastName": f"Lab {store.run_id}",
                "email": login,
                "login": login,
            },
            password,
        )
        user_id_value = user.get("id")
        if not isinstance(user_id_value, str):
            raise LabSafetyError("Okta did not return an ephemeral user ID")
        user_id = user_id_value
        record["active_trace"]["user_id"] = user_id
        store.save(state)
        user = _wait_for_active_user(client, user_id)
        _require_isolated_user(client, user)
        totp = _enroll_ephemeral_totp(client, user_id)
        record["active_trace"]["totp_activated_at"] = _now()
        store.save(state)

        client.activate_application(app_id)
        record["active_trace"]["app_activated_at"] = _now()
        store.save(state)
        active_application = client.get_application(app_id)
        _validate_application_identity(
            active_application,
            app_id=app_id,
            app_key=case.app_key,
            label=record["label"],
        )
        if active_application.get("status") != "ACTIVE":
            raise LabSafetyError("OIN app did not become ACTIVE")

        client.assign_application_user(
            app_id,
            user_id,
            login,
            profile=case.assignment_profile,
        )
        record["active_trace"]["user_assigned_at"] = _now()
        record["active_trace"]["assignment_profile_fields"] = sorted(
            (case.assignment_profile or {}).keys()
        )
        store.save(state)
        assigned_users = client.list_application_users(app_id)
        if (
            len(assigned_users) != 1
            or assigned_users[0].get("id") != user_id
            or assigned_users[0].get("scope") != "USER"
        ):
            raise LabSafetyError("OIN app does not have exactly the ephemeral user")
        app_links = _application_links(client, user_id, app_id, store.tenant_url)
        selected_link, selected_index = _select_application_link(
            app_links,
            probe_app_label=record["label"],
            label_suffix=case.app_link_label_suffix,
        )
        link_selection = {
            "available_count": len(app_links),
            "available_labels": [link.label for link in app_links],
            "selected_index": selected_index,
            "selected_label": selected_link.label,
        }
        record["active_trace"]["app_link_selection"] = link_selection
        store.save(state)
        observation = dict(
            browser_tracer(
                BrowserTraceInput(
                    tenant_url=store.tenant_url,
                    app_link_url=selected_link.url,
                    login=login,
                    password=password,
                    totp_secret=totp.shared_secret,
                    totp_activation_counter=totp.activation_counter,
                )
            )
        )
        _require_saml_response_observation(observation, store.tenant_url)
        store.write_capture(
            "active-raw",
            case.case_id,
            json.dumps(observation, indent=2, sort_keys=True) + "\n",
        )
        public_observation = public_trace_observation(observation)
        public_observation["app_link_selection"] = link_selection
        store.write_capture(
            "active-review",
            case.case_id,
            json.dumps(public_observation, indent=2, sort_keys=True) + "\n",
        )
        record["active_trace"]["captured_at"] = _now()
        record["active_trace"]["observation_sha256"] = hashlib.sha256(
            json.dumps(observation, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        store.save(state)
    except BaseException as error:
        original_error = error
    finally:
        if user_id is None and user_creation_attempted:
            existing_user: dict[str, Any] | None
            try:
                existing_user = client.get_user(login)
            except OktaNotFound:
                existing_user = None
                record["active_trace"]["user_absent_at"] = _now()
                store.save(state)
            except Exception as error:  # cleanup must continue to the app
                cleanup_errors.append(f"user lookup: {type(error).__name__}")
                existing_user = None
            if existing_user is not None and isinstance(existing_user.get("id"), str):
                user_id = existing_user["id"]
        if safe_to_cleanup_app:
            try:
                assigned_users = client.list_application_users(app_id)
                if assigned_users:
                    if (
                        user_id is None
                        or len(assigned_users) != 1
                        or assigned_users[0].get("id") != user_id
                    ):
                        safe_to_cleanup_app = False
                        cleanup_errors.append(
                            "application has an unexpected user assignment"
                        )
                    else:
                        client.unassign_application_user(app_id, user_id)
            except OktaNotFound:
                pass
            except Exception as error:
                safe_to_cleanup_app = False
                cleanup_errors.append(
                    f"user assignment cleanup: {type(error).__name__}"
                )
        if user_id is not None:
            try:
                _delete_ephemeral_user(client, user_id, login)
                record["active_trace"]["user_deleted_at"] = _now()
                store.save(state)
            except Exception as error:
                cleanup_errors.append(f"user deletion: {type(error).__name__}")
        if safe_to_cleanup_app:
            try:
                live_application = client.get_application(app_id)
                _validate_application_identity(
                    live_application,
                    app_id=app_id,
                    app_key=case.app_key,
                    label=record["label"],
                )
                if live_application.get("status") == "ACTIVE":
                    client.deactivate_application(app_id)
                    live_application = client.get_application(app_id)
                if live_application.get("status") != "INACTIVE":
                    raise LabSafetyError("OIN app did not return to INACTIVE")
                client.delete_application(app_id)
                try:
                    client.get_application(app_id)
                except OktaNotFound:
                    record["deleted_at"] = _now()
                    record["active_trace"]["app_deleted_at"] = _now()
                    store.save(state)
                else:
                    raise LabSafetyError("OIN app still exists after active trace")
            except OktaNotFound:
                record["deleted_at"] = record.get("deleted_at") or _now()
                store.save(state)
            except Exception as error:
                cleanup_errors.append(f"application cleanup: {type(error).__name__}")

    if cleanup_errors:
        detail = ", ".join(cleanup_errors)
        if original_error is not None:
            raise LabSafetyError(
                f"active trace failed with {type(original_error).__name__}; "
                f"cleanup also failed: {detail}"
            ) from original_error
        raise LabSafetyError(f"active trace cleanup failed: {detail}")
    if original_error is not None:
        raise original_error
    return state
