"""Okta source configuration and category resource composition."""

from typing import Union

import dlt
from dlt.sources.helpers.rest_client.paginators import HeaderLinkPaginator

from .auth import (
    OktaAppCredentials,
    OktaEncodedAppCredentials,
    OktaTokenCredentials,
    _request_auth,
)
from .client import ClientPool
from .main import app
from .resources import (
    applications,
    authorization,
    federation,
    identities,
    organization,
    policies,
)
from .source_context import (
    APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE,
    APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE,
    APPLICATION_USERS_PAGE_SIZE,
    GROUP_PUSH_MAPPINGS_PAGE_SIZE,
    GROUPS_PAGE_SIZE,
    IDENTITY_PROVIDER_USERS_PAGE_SIZE,
    SourceContext,
    _tenant_domain_from_base_url,
)
from .telemetry import NullTelemetryRecorder, Telemetry
from .utils.http import (
    DEFAULT_ENDPOINT_CONCURRENCY,
    DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
)


@app.source(name="okta", max_table_nesting=0)
def source(
    credentials: Union[
        OktaAppCredentials, OktaEncodedAppCredentials, OktaTokenCredentials
    ] = dlt.secrets.value,
    application_users_page_size: int = APPLICATION_USERS_PAGE_SIZE,
    groups_page_size: int = GROUPS_PAGE_SIZE,
    application_group_assignments_page_size: int = (
        APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE
    ),
    group_push_mappings_page_size: int = GROUP_PUSH_MAPPINGS_PAGE_SIZE,
    identity_provider_users_page_size: int = IDENTITY_PROVIDER_USERS_PAGE_SIZE,
    endpoint_concurrency: int = DEFAULT_ENDPOINT_CONCURRENCY,
    rate_limit_max_elapsed_seconds: float = DEFAULT_RATE_LIMIT_MAX_ELAPSED_SECONDS,
    rate_limit_remaining_reserve: int = DEFAULT_RATE_LIMIT_REMAINING_RESERVE,
    telemetry: Telemetry | None = None,
) -> tuple:
    """DLT source, defines Okta collection resources and transformers.

    Args:
        credentials: Okta API credentials based on key path, encoded key or SSWS for authentication.
        application_users_page_size: Users requested per application-users page.
        groups_page_size: Groups requested per expanded groups page.
        application_group_assignments_page_size: Groups requested per application page.
        group_push_mappings_page_size: Mappings requested per group-push page.
        identity_provider_users_page_size: Users requested per identity-provider page.
        endpoint_concurrency: Maximum simultaneous requests for each endpoint family.
        rate_limit_max_elapsed_seconds: Maximum retry window for an individual 429 request.
        rate_limit_remaining_reserve: Requests retained as headroom in each observed window.
        telemetry: Internal collection-phase telemetry recorder.
    Returns:
        Tuple of DLT resources and transformers registered for Okta.
    """

    if not 1 <= application_users_page_size <= APPLICATION_USERS_PAGE_SIZE:
        raise ValueError(
            "application_users_page_size must be between 1 and "
            f"{APPLICATION_USERS_PAGE_SIZE}"
        )
    if not 1 <= groups_page_size <= GROUPS_PAGE_SIZE:
        raise ValueError(f"groups_page_size must be between 1 and {GROUPS_PAGE_SIZE}")
    if not (
        APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE
        <= application_group_assignments_page_size
        <= APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE
    ):
        raise ValueError(
            "application_group_assignments_page_size must be between "
            f"{APPLICATION_GROUP_ASSIGNMENTS_MIN_PAGE_SIZE} and "
            f"{APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE}"
        )
    if not 1 <= group_push_mappings_page_size <= GROUP_PUSH_MAPPINGS_PAGE_SIZE:
        raise ValueError(
            "group_push_mappings_page_size must be between 1 and "
            f"{GROUP_PUSH_MAPPINGS_PAGE_SIZE}"
        )
    if not 1 <= identity_provider_users_page_size <= IDENTITY_PROVIDER_USERS_PAGE_SIZE:
        raise ValueError(
            "identity_provider_users_page_size must be between 1 and "
            f"{IDENTITY_PROVIDER_USERS_PAGE_SIZE}"
        )
    if endpoint_concurrency < 1:
        raise ValueError("endpoint_concurrency must be at least 1")
    if rate_limit_max_elapsed_seconds <= 0:
        raise ValueError("rate_limit_max_elapsed_seconds must be positive")
    if rate_limit_remaining_reserve < 0:
        raise ValueError("rate_limit_remaining_reserve cannot be negative")

    telemetry = telemetry or NullTelemetryRecorder()
    telemetry.set_effective_settings(
        {
            "application_users_page_size": application_users_page_size,
            "groups_page_size": groups_page_size,
            "application_group_assignments_page_size": (
                application_group_assignments_page_size
            ),
            "group_push_mappings_page_size": group_push_mappings_page_size,
            "identity_provider_users_page_size": identity_provider_users_page_size,
            "endpoint_concurrency": endpoint_concurrency,
            "rate_limit_max_elapsed_seconds": rate_limit_max_elapsed_seconds,
            "rate_limit_remaining_reserve": rate_limit_remaining_reserve,
        }
    )

    pool = ClientPool(
        base_url=credentials.base_url,
        auth=_request_auth(credentials),
        paginator=HeaderLinkPaginator(),
        endpoint_concurrency=endpoint_concurrency,
        rate_limit_max_elapsed_seconds=rate_limit_max_elapsed_seconds,
        rate_limit_remaining_reserve=rate_limit_remaining_reserve,
        telemetry=telemetry,
    )

    ctx = SourceContext(
        pool=pool,
        tenant_domain=_tenant_domain_from_base_url(credentials.base_url),
        telemetry=telemetry,
        application_users_page_size=application_users_page_size,
        groups_page_size=groups_page_size,
        application_group_assignments_page_size=(
            application_group_assignments_page_size
        ),
        group_push_mappings_page_size=group_push_mappings_page_size,
        identity_provider_users_page_size=identity_provider_users_page_size,
    )
    applications_resource = applications.applications(ctx)
    return (
        *organization.all_resources(ctx),
        *identities.all_resources(ctx),
        *applications.all_resources(applications_resource, ctx),
        *authorization.all_resources(ctx),
        *policies.all_resources(ctx),
        *federation.all_resources(applications_resource, ctx),
    )
