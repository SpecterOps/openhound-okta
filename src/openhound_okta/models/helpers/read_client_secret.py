from collections.abc import Iterator

from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties

from openhound_okta.kinds import edges as ek


def read_client_secret_edges(role_assignment) -> Iterator[Edge]:
    """Generate read-client-secret edges for role assignments."""

    if role_assignment.type == "APP_ADMIN":
        embedded = role_assignment.embedded
        if (
            embedded
            and embedded.targets
            and embedded.targets.catalog
            and embedded.targets.catalog.apps
        ):
            app_ids = [app.id for app in embedded.targets.catalog.apps if app.id]
        else:
            app_ids = [app_id for (app_id,) in role_assignment._lookup.all_applications()]

        for app_id in app_ids:
            for (secret_id,) in role_assignment._lookup.application_secret_ids(app_id):
                yield Edge(
                    kind=ek.READ_CLIENT_SECRET,
                    start=EdgePath(value=role_assignment.source_id, match_by="id"),
                    end=EdgePath(value=secret_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    elif role_assignment.type in ["API_ACCESS_MANAGEMENT_ADMIN", "READ_ONLY_ADMIN"]:
        for (app_id,) in role_assignment._lookup.all_applications():
            for (secret_id,) in role_assignment._lookup.application_secret_ids(app_id):
                yield Edge(
                    kind=ek.READ_CLIENT_SECRET,
                    start=EdgePath(value=role_assignment.source_id, match_by="id"),
                    end=EdgePath(value=secret_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )

    elif (
        role_assignment.type == "CUSTOM"
        and role_assignment.role
        and role_assignment.resource_set
        and role_assignment._lookup.has_role_permission(
            role_assignment.role, "okta.apps.clientCredentials.read"
        )
    ):
        for app_id in role_assignment._lookup.resource_set_application_ids(
            role_assignment.resource_set
        ):
            for (secret_id,) in role_assignment._lookup.application_secret_ids(app_id):
                yield Edge(
                    kind=ek.READ_CLIENT_SECRET,
                    start=EdgePath(value=role_assignment.source_id, match_by="id"),
                    end=EdgePath(value=secret_id, match_by="id"),
                    properties=EdgeProperties(traversable=True),
                )
