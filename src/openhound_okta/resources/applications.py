"""Okta applications collection resources and helpers."""

import hashlib
import json
import logging
from collections.abc import Iterator, Mapping
from typing import Any, Callable

import dlt
import requests
from dlt.extract import DltResource

from ..main import app
from ..models import (
    ApiService,
    ApiServiceSecrets,
    Application,
    ApplicationGrant,
    ApplicationGroupMapping,
    ApplicationJWKS,
    ApplicationSecrets,
    ApplicationUser,
    ClientApplication,
    GroupAssignedApp,
)
from ..models.application_users import (
    ALWAYS_COLLECTED_APP_USERS,
    APPLICATION_USER_ITEM_SKIPPED_KEYS,
    APPLICATION_USER_PROFILE_SKIPPED_KEYS,
)
from ..source_context import APPLICATION_GRANTS_ACCESS_DENIED_LIMIT, SourceContext
from ..telemetry import NullTelemetryRecorder
from ..utils.http import OktaRetryExhaustedError
from .authorization import client_role_assignments
from .federation import _saml_metadata_fields

logger = logging.getLogger(__name__)


def _application_group_assignment_fingerprint(
    assignment: Mapping[str, object],
) -> str:
    """Return a type-preserving canonical fingerprint for duplicate evidence."""
    evidence = {
        "assignment_last_updated": assignment.get("lastUpdated"),
        "assignment_priority": assignment.get("priority"),
        "assignment_profile": assignment.get("profile"),
    }
    try:
        canonical_evidence = json.dumps(
            evidence,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "application-group assignment has non-JSON duplicate evidence"
        ) from exc

    return hashlib.sha256(canonical_evidence.encode("utf-8")).hexdigest()


def application_group_assignment_rows(application: Application, ctx: SourceContext):
    """Stream authoritative assignments while retaining compact duplicate state."""
    assignment_fingerprints: dict[str, str] = {}
    duplicate_count = 0

    for page in ctx.pool.paginate(
        f"/api/v1/apps/{application.id}/groups",
        params={"limit": ctx.application_group_assignments_page_size},
    ):
        for assignment in page:
            if not isinstance(assignment, Mapping):
                raise ValueError(
                    "application-group assignment without a usable group ID "
                    f"for application {application.id}"
                )

            group_id = assignment.get("id")
            if not isinstance(group_id, str) or not group_id.strip():
                raise ValueError(
                    "application-group assignment without a usable group ID "
                    f"for application {application.id}"
                )
            group_id = group_id.strip()
            fingerprint = _application_group_assignment_fingerprint(assignment)

            row = {
                "id": application.id,
                "group_id": group_id,
                "name": application.name,
                "label": application.label,
                "status": application.status,
                "lastUpdated": application.last_updated,
                "app_sign_on_mode": application.sign_on_mode,
                "assignment_last_updated": assignment.get("lastUpdated"),
                "assignment_priority": assignment.get("priority"),
                "assignment_profile": assignment.get("profile"),
            }
            previous = assignment_fingerprints.get(group_id)
            if previous is None:
                assignment_fingerprints[group_id] = fingerprint
                yield row
            elif previous == fingerprint:
                duplicate_count += 1
            else:
                raise ValueError(
                    "conflicting application-group assignments for "
                    f"application {application.id} and group {group_id}"
                )

    if duplicate_count:
        logger.warning(
            "deduplicated %d identical application-group assignment rows for application %s",
            duplicate_count,
            application.id,
            extra={"resource": "group_assigned_apps", "phase": "collect"},
        )


# This authoritative transformer and its shared parent use DLT directly so
# OpenHound's best-effort wrapper cannot publish a partial replacement snapshot.
@dlt.transformer(
    name="group_assigned_apps",
    columns=GroupAssignedApp,
    parallelized=True,
    write_disposition="replace",
)
def group_assigned_apps(application: Application, ctx: SourceContext):
    """Fetch authoritative group assignments for an Okta application."""
    try:
        yield from application_group_assignment_rows(application, ctx)
    except Exception:
        logger.error(
            "authoritative application-group assignment collection failed",
            extra={"resource": "group_assigned_apps", "phase": "resource_iteration"},
        )
        raise


app.dlt_resources.append(group_assigned_apps)


@dlt.resource(name="applications", columns=Application, parallelized=True)
def applications(ctx: SourceContext):
    """DLT resource, fetches Okta applications via GET /api/v1/apps.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        application (Application): Okta application record.
    """
    for page in ctx.pool.paginate(
        "/api/v1/apps", params={"limit": ctx.applications_page_size}
    ):
        for item in page:
            if item.get("signOnMode") == "SAML_2_0":
                item = {**item, **_saml_metadata_fields(ctx, item)}
            yield item


app.dlt_resources.append(applications)


def _user_name_template_value(user_name_template: object) -> str | None:
    """Return the template string of a user name template, from a mapping or model.

    Args:
        user_name_template: Mapping or object with a template attribute.
    """
    if isinstance(user_name_template, Mapping):
        value = user_name_template.get("template")
        return value if isinstance(value, str) else None
    value = getattr(user_name_template, "template", None)
    return value if isinstance(value, str) else None


@app.transformer(name="application_jwks", columns=ApplicationJWKS, parallelized=True)
def application_jwks(application: Application, ctx: SourceContext):
    """DLT transformer, yields an application's JWKs; see application_jwk_rows.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool.

    Yields:
        JWK rows tagged with app_id and app_name.
    """
    yield from application_jwk_rows(application, ctx)


def _embedded_application_jwk_rows(application: Application):
    """Yield the JWKs embedded in the application's OAuth client settings.

    Args:
        application: Parent application record.

    Yields:
        One row per embedded key, tagged with app_id and app_name.
    """
    oauth_client = application.settings.oauth_client if application.settings else None
    if not oauth_client or not oauth_client.jwks:
        return

    for key in oauth_client.jwks.keys:
        yield {
            "app_id": application.id,
            "app_name": application.name,
            **key.model_dump(),
        }


def _jwk_page_items(page: object):
    """Extract the key list from a JWKS page in any of Okta's response shapes.

    Args:
        page: A page from the credentials/jwks endpoint.

    Returns:
        The keys list, or the page itself when it is already a list.
    """
    if isinstance(page, Mapping):
        keys = page.get("keys")
        if isinstance(keys, list):
            return keys
        jwks = page.get("jwks")
        if isinstance(jwks, Mapping) and isinstance(jwks.get("keys"), list):
            return jwks["keys"]
        return []
    return page


def application_jwk_rows(application: Application, ctx: SourceContext):
    """Yield an application's JWKs, preferring the API over the embedded copy.

    Only applications with embedded JWKs are queried. API errors other than 404
    are logged; on any error the embedded keys are yielded instead.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool.

    Yields:
        JWK rows tagged with app_id and app_name.

    Raises:
        OktaRetryExhaustedError: If the request exhausted its retries.
    """
    embedded_rows = list(_embedded_application_jwk_rows(application))
    if not embedded_rows:
        return

    try:
        rows = []
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/credentials/jwks"
        ):
            for item in _jwk_page_items(page):
                if isinstance(item, Mapping):
                    rows.append(
                        {
                            "app_id": application.id,
                            "app_name": application.name,
                            **item,
                        }
                    )
        yield from rows or embedded_rows
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if status_code != 404:
            logger.error(
                "Error fetching application JWKs for %s: %s",
                application.id,
                e,
                extra={"resource": "application_jwks", "phase": "defer"},
            )
        yield from embedded_rows


@app.transformer(name="application_grants", columns=ApplicationGrant)
def application_grants(
    application: Application, ctx: SourceContext
) -> Iterator[dict[str, Any]]:
    """DLT transformer, fetches OAuth 2.0 grants of an OIDC or service
    application via GET /apps/{applicationId}/grants.

    Reading app grants requires the Super Administrator role. Each
    access-denied (403) response is counted by the shared
    ctx.application_grants_breaker; once it trips, grant collection is skipped
    for all remaining applications without issuing further requests.

    Args:
        application: Okta application record.
        ctx: SourceContext containing the REST client and the grant breaker.

    Yields:
        grant (dict): Application grant record enriched with an ``app_id`` key.

    Raises:
        OktaRetryExhaustedError: If retries were exhausted for a grants
            request.
    """
    oauth_client = application.settings.oauth_client if application.settings else None
    if application.sign_on_mode != "OPENID_CONNECT" and not (
        oauth_client and oauth_client.application_type == "service"
    ):
        return

    breaker = ctx.application_grants_breaker
    if breaker.tripped:
        return

    try:
        for page in ctx.pool.paginate(f"/api/v1/apps/{application.id}/grants"):
            breaker.record_success()
            for item in page:
                yield {"app_id": application.id, **item}
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if status_code == 403:
            if breaker.record_access_denied():
                logger.warning(
                    "Skipping app grant collection after %d consecutive "
                    "access-denied responses; oauth_scopes and OIDC "
                    "application attack path edges will be missing.",
                    APPLICATION_GRANTS_ACCESS_DENIED_LIMIT,
                    extra={"resource": "application_grants", "phase": "defer"},
                )
            else:
                logger.debug(
                    "Access denied fetching application grants for %s",
                    application.id,
                    extra={"resource": "application_grants", "phase": "defer"},
                )
        elif status_code != 404:
            logger.error(
                "Error fetching application grants for %s: %s",
                application.id,
                e,
                extra={"resource": "application_grants", "phase": "defer"},
            )


@app.transformer(
    name="application_group_push_mappings",
    columns=ApplicationGroupMapping,
    parallelized=True,
)
def application_group_push_mappings(application: Application, ctx: SourceContext):
    """DLT transformer, fetches group push mappings of GROUP_PUSH applications.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool and page size.

    Yields:
        Mapping rows with the target group name resolved.
    """
    if "GROUP_PUSH" in application.features:
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/group-push/mappings",
            params={"limit": ctx.group_push_mappings_page_size},
        ):
            for item in page:
                yield application_group_push_mapping_row(application, item, ctx)


def application_group_push_mapping_row(
    application: Application,
    mapping: Mapping[str, object],
    ctx: SourceContext,
) -> dict[str, object]:
    """Build a group push mapping row, adding the target group's name when readable.

    Args:
        application: Parent application record.
        mapping: Raw mapping record.
        ctx: Source context providing the client pool.

    Returns:
        The mapping tagged with app_id and app_name, plus target_group_name if
        the target group could be fetched.

    Raises:
        OktaRetryExhaustedError: If the group request exhausted its retries.
    """
    row = {"app_id": application.id, "app_name": application.name, **mapping}
    target_group_id = mapping.get("targetGroupId")
    if not isinstance(target_group_id, str):
        return row

    try:
        target_group = ctx.pool.get(f"/api/v1/groups/{target_group_id}").json()
    except OktaRetryExhaustedError:
        raise
    except Exception as e:
        logger.error(
            "Error fetching target group %s for group push mapping %s: %s",
            target_group_id,
            mapping.get("id"),
            e,
            extra={"resource": "application_group_push_mappings", "phase": "defer"},
        )
        return row

    if not isinstance(target_group, Mapping):
        return row

    profile = target_group.get("profile")
    if not isinstance(profile, Mapping):
        return row

    target_group_name = profile.get("name")
    if isinstance(target_group_name, str) and target_group_name:
        row["target_group_name"] = target_group_name

    return row


@app.transformer(
    name="application_secrets", columns=ApplicationSecrets, parallelized=True
)
def application_secrets(application: Application, ctx: SourceContext):
    """DLT transformer, fetches client secrets of client_secret_basic applications.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool.

    Yields:
        Secret rows tagged with app_id and app_name.
    """
    oauth_client = (
        application.credentials.oauth_client if application.credentials else None
    )
    if (
        oauth_client
        and oauth_client.token_endpoint_auth_method == "client_secret_basic"
    ):
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/credentials/secrets"
        ):
            for item in page:
                # Okta always returns the plaintext client_secret here and offers
                # no way to suppress it; secret_hash is enough to model the secret.
                yield {
                    "app_id": application.id,
                    "app_name": application.name,
                    **{k: v for k, v in item.items() if k != "client_secret"},
                }


@app.transformer(
    name="api_service_secrets", columns=ApiServiceSecrets, parallelized=True
)
def api_service_secrets(api_service: ApiService, ctx: SourceContext):
    """DLT transformer, fetches client secrets of API service integrations.

    Args:
        api_service: Parent API service integration record.
        ctx: Source context providing the client pool.

    Yields:
        Secret rows tagged with app_id and app_name.
    """
    yield from api_service_secret_rows(api_service, ctx)


def api_service_secret_rows(api_service: ApiService, ctx: SourceContext):
    """Yield client secret rows for one API service integration.

    Args:
        api_service: Parent API service integration record.
        ctx: Source context providing the client pool.

    Yields:
        Secret rows tagged with app_id and app_name.
    """
    for page in ctx.pool.paginate(
        f"/integrations/api/v1/api-services/{api_service.id}/credentials/secrets"
    ):
        for item in page:
            # Okta already redacts this value (e.g. "***************bHuy"), but it
            # is dropped anyway, matching the application secrets handling.
            yield {
                "app_id": api_service.id,
                "app_name": api_service.name,
                **{k: v for k, v in item.items() if k != "client_secret"},
            }


@app.transformer(name="application_users", columns=ApplicationUser, parallelized=True)
def application_users(application: Application, ctx: SourceContext):
    """DLT transformer, fetches users assigned to an Okta application via GET /apps/{applicationId}/users.

    Args:
        application (Application): Okta application record.
        ctx (SourceContext): SourceContext containing the REST client for API calls.

    Yields:
        _type_: _description_
    """
    yield from application_user_rows(application, ctx)


def application_user_rows(application: Application, ctx: SourceContext):
    """Yield user assignment rows for one application, tagged with app details.

    Records the stream outcome in telemetry and re-raises any failure.

    Args:
        application: Parent application record.
        ctx: Source context providing the client pool, page size, and telemetry.

    Yields:
        Assignment rows with app_* fields prepended.
    """
    row_count = 0
    telemetry = getattr(ctx, "telemetry", NullTelemetryRecorder())
    sign_on = application.settings.sign_on if application.settings else None
    user_name_template = (
        application.credentials.user_name_template if application.credentials else None
    )
    # Application details are the same on every row, so build them once.
    app_fields = {
        "app_id": application.id,
        "app_features": application.features,
        "app_name": application.name,
        "app_status": getattr(application, "status", None),
        "app_settings": application.settings.app if application.settings else None,
        "app_sign_on_mode": application.sign_on_mode,
        "app_subject_name_id_template": (
            sign_on.subject_name_id_template if sign_on else None
        ),
        "app_subject_name_id_format": (
            sign_on.subject_name_id_format if sign_on else None
        ),
        "app_user_name_template": _user_name_template_value(user_name_template),
    }
    try:
        for page in ctx.pool.paginate(
            f"/api/v1/apps/{application.id}/users",
            params={"limit": ctx.application_users_page_size},
        ):
            for item in page:
                row_count += 1
                yield {
                    **app_fields,
                    # Profile attributes nobody reads are dropped to save
                    # space: this is the largest collected table.
                    "profile": {
                        key: value
                        for key, value in (item.get("profile") or {}).items()
                        if key not in APPLICATION_USER_PROFILE_SKIPPED_KEYS
                    },
                    # Likewise the assignment timestamps, _links and _embedded
                    # copies are dropped; the trimmed profile above stays.
                    **{
                        key: value
                        for key, value in item.items()
                        if key not in APPLICATION_USER_ITEM_SKIPPED_KEYS
                        and key != "profile"
                    },
                }
    except Exception:
        telemetry.record_application_stream("failed")
        logger.error(
            "Application user collection failed app_id=%s rows_streamed=%s",
            application.id,
            row_count,
            exc_info=True,
        )
        raise
    telemetry.record_application_stream("completed")
    logger.info(
        "Application user collection completed app_id=%s rows=%s",
        application.id,
        row_count,
    )


def app_user_collection_filter(
    app_ids: frozenset[str],
) -> Callable[[Application], bool]:
    """Build the DLT item filter applied when application-user collection is limited.

    Args:
        app_ids: Okta application IDs collected in addition to ALWAYS_COLLECTED_APP_USERS.

    Returns:
        Predicate that keeps applications whose name is always collected or whose ID is listed.
    """

    def collects_app_users(application: Application) -> bool:
        return (
            application.name in ALWAYS_COLLECTED_APP_USERS or application.id in app_ids
        )

    return collects_app_users


@app.resource(name="client_applications", columns=ClientApplication, parallelized=True)
def client_applications(ctx: SourceContext):
    """DLT resource, fetches OAuth 2.0 clients via GET /oauth2/v1/clients.

    Args:
        ctx: Source context providing the client pool.

    Yields:
        client (ClientApplication): Client application record.
    """
    for page in ctx.pool.paginate("/oauth2/v1/clients"):
        for item in page:
            yield item


@app.resource(name="api_services", columns=ApiService, parallelized=True)
def api_services(ctx: SourceContext) -> Iterator[dict[str, Any]]:
    """DLT resource, fetches Okta API service integrations via
    GET /integrations/api/v1/api-services.

    Listing API service integrations requires the Super Administrator role.
    An access-denied (403) response is logged as a warning and treated as an
    empty listing; all other HTTP errors propagate.

    Args:
        ctx: SourceContext containing the REST client for API calls.

    Yields:
        api_service (ApiService): API service integration records.
    """
    try:
        for page in ctx.pool.paginate("/integrations/api/v1/api-services"):
            for item in page:
                yield item
    except requests.HTTPError as e:
        status_code = getattr(e.response, "status_code", None)
        if status_code != 403:
            raise
        logger.warning(
            "Access denied listing API service integrations; skipping them.",
            extra={"resource": "api_services", "phase": "collect"},
        )


def all_resources(
    applications_resource: DltResource,
    ctx: SourceContext,
    *,
    limit_app_user_collection: bool = False,
    app_user_collection_app_ids: list[str] | None = None,
) -> tuple[DltResource, ...]:
    """Compose application pipelines from the shared, enriched applications parent."""
    client_apps_resource = client_applications(ctx)
    api_services_resource = api_services(ctx)
    application_users_resource = applications_resource | application_users(ctx)
    if limit_app_user_collection:
        application_users_resource.add_filter(
            app_user_collection_filter(frozenset(app_user_collection_app_ids or ())),
            insert_at=0,
        )
    return (
        client_apps_resource,
        client_apps_resource | client_role_assignments(ctx),
        applications_resource,
        applications_resource | group_assigned_apps(ctx),
        applications_resource | application_grants(ctx),
        application_users_resource,
        applications_resource | application_jwks(ctx),
        applications_resource | application_secrets(ctx),
        applications_resource | application_group_push_mappings(ctx),
        api_services_resource,
        api_services_resource | api_service_secrets(ctx),
    )
