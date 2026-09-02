from functools import lru_cache
import json
import re
from typing import Any
from urllib.parse import parse_qs, urlparse

import duckdb
from duckdb import DuckDBPyConnection, Error as DuckDBError
from openhound.core.lookup import LookupManager


USER_SAML_CONTEXT_CACHE_MAXSIZE = 128


def _normalize_user_profile(profile: Any) -> dict[str, Any] | None:
    if isinstance(profile, str):
        try:
            profile = json.loads(profile)
        except (json.JSONDecodeError, TypeError):
            return None
    return profile if isinstance(profile, dict) else None


class OktaLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "okta"):
        super().__init__(client, schema)
        self.schema = schema
        self.client = client
        self.tenant_domain: str | None = None
        self._user_saml_context_cache: dict[
            str, tuple[str | None, dict[str, Any] | None]
        ] = {}

    @lru_cache
    def _table_exists(self, table_name: str) -> bool:
        row = self.client.execute(
            """SELECT 1 FROM information_schema.tables
               WHERE table_schema = ? AND table_name = ?
               LIMIT 1""",
            [self.schema, table_name],
        ).fetchone()
        return row is not None

    @lru_cache
    def _column_exists(self, table_name: str, column_name: str) -> bool:
        row = self.client.execute(
            """SELECT 1 FROM information_schema.columns
               WHERE table_schema = ? AND table_name = ? AND column_name = ?
               LIMIT 1""",
            [self.schema, table_name, column_name],
        ).fetchone()
        return row is not None

    @lru_cache
    def org_id(self) -> str | None:
        res = self._find_single_object(f"""SELECT id FROM {self.schema}.organization""")
        return res

    @lru_cache
    def has_role_permission(self, role_id: str, permission: str) -> bool:
        res = self._find_single_object(
            f"""SELECT label FROM {self.schema}.custom_role_permissions WHERE role_id = ? AND label = ?""",
            [role_id, permission],
        )
        return res

    @lru_cache
    def custom_role_permissions(self, role_id: str) -> tuple[str, ...]:
        if not self._table_exists("custom_role_permissions"):
            return ()

        rows = self._find_all_objects(
            f"""SELECT label FROM {self.schema}.custom_role_permissions
                WHERE role_id = ?""",
            [role_id],
        )
        return tuple(label for (label,) in rows)

    @lru_cache
    def application_by_id(self, app_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def group_by_id(self, group_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.groups WHERE id = ?""",
            [group_id],
        )
        return res

    @lru_cache
    def saml_group_assignment_group_ids(self, app_id: str) -> tuple[str, ...]:
        """Return one app's authoritative group assignments in canonical order."""

        try:
            rows = self._find_all_objects(
                f"""
                SELECT DISTINCT group_id
                FROM {self.schema}.group_assigned_apps
                WHERE id = ?
                ORDER BY group_id
                """,
                [app_id],
            )
        except DuckDBError as exc:
            raise RuntimeError(
                "SAML group eligibility conversion requires authoritative "
                "application-group assignments"
            ) from exc
        return tuple(group_id for (group_id,) in rows)

    @lru_cache
    def application_settings(self, app_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT settings FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def application_name(self, app_id: str) -> str | None:
        return self._find_single_object(
            f"""SELECT name FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )

    @lru_cache
    def all_groups(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.groups""")
        return res

    @lru_cache
    def non_admin_groups(self):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.non_admin_groups"""
        )
        return res

    @lru_cache
    def all_users(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.users""")
        return res

    def iter_user_saml_accounts(self):
        """Stream authoritative Okta account IDs, lifecycle states, and logins."""

        cursor = self.client.cursor()
        try:
            cursor.execute(
                f"""
                SELECT id, status, json_extract_string(profile, '$.login') AS login
                FROM {self.schema}.users
                ORDER BY id
                """
            )
            while rows := cursor.fetchmany(1000):
                yield from rows
        finally:
            cursor.close()

    @lru_cache
    def directly_linked_saml_account_ids(self, idp_id: str) -> frozenset[str]:
        """Return native Okta accounts already linked to one inbound IdP."""

        rows = self._find_all_objects(
            f"""
            SELECT id
            FROM {self.schema}.identity_provider_users
            WHERE idp_id = ?
            ORDER BY id
            """,
            [idp_id],
        )
        return frozenset(account_id for (account_id,) in rows)

    @lru_cache
    def user_status(self, user_id: str) -> str | None:
        try:
            return self._find_single_object(
                f"""SELECT status FROM {self.schema}.users WHERE id = ?""",
                [user_id],
            )
        except DuckDBError:
            return None

    @lru_cache
    def user_profile(self, user_id: str) -> dict[str, Any] | None:
        try:
            profile = self._find_single_object(
                f"""SELECT profile FROM {self.schema}.users WHERE id = ?""",
                [user_id],
            )
        except DuckDBError:
            return None
        return _normalize_user_profile(profile)

    def user_saml_context(
        self, user_id: str
    ) -> tuple[str | None, dict[str, Any] | None] | None:
        """Return source-user lifecycle and profile in one point statement."""

        cached = self._user_saml_context_cache.get(user_id)
        if cached is not None:
            # Reinsert cache hits so the first entry remains the least recently used.
            del self._user_saml_context_cache[user_id]
            self._user_saml_context_cache[user_id] = cached
            return cached

        try:
            row = self.client.execute(
                f"""SELECT status, profile
                    FROM {self.schema}.users
                    WHERE id = ?""",
                [user_id],
            ).fetchone()
        except DuckDBError:
            return None
        if row is None:
            return None

        status, profile = row
        context = status, _normalize_user_profile(profile)
        if len(self._user_saml_context_cache) >= USER_SAML_CONTEXT_CACHE_MAXSIZE:
            oldest_user_id = next(iter(self._user_saml_context_cache))
            del self._user_saml_context_cache[oldest_user_id]
        self._user_saml_context_cache[user_id] = context
        return context

    @lru_cache
    def saml_claim_mappings(self, app_id: str) -> tuple[dict[str, Any], ...]:
        try:
            available_columns = {
                row[0]
                for row in self._find_all_objects(
                    f"""DESCRIBE {self.schema}.saml_claim_mappings"""
                )
            }
        except DuckDBError:
            return ()
        required_columns = {
            "id",
            "app_id",
            "claim_name",
            "mapping_type",
            "claim_type",
            "expression",
        }
        if not required_columns <= available_columns:
            return ()
        selected_columns = [
            column
            for column in (
                "id",
                "claim_name",
                "mapping_type",
                "mapping_origin",
                "claim_type",
                "source_property",
                "expression",
                "name_id_format",
                "format",
                "format_was_omitted",
                "name_format",
                "name_format_was_omitted",
            )
            if column in available_columns
        ]
        rows = self._find_all_objects(
            f"""
            SELECT {", ".join(selected_columns)}
            FROM {self.schema}.saml_claim_mappings
            WHERE app_id = ?
            ORDER BY TRY_CAST(regexp_extract(id, '([0-9]+)$', 1) AS INTEGER), id
            """,
            [app_id],
        )
        return tuple(dict(zip(selected_columns, row, strict=True)) for row in rows)

    @lru_cache
    def non_admin_users(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.non_admin_users""")
        return res

    @lru_cache
    def all_api_services(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.api_services""")
        return res

    @lru_cache
    def all_applications(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.applications""")
        return res

    @lru_cache
    def non_admin_apps(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.non_admin_apps""")
        return res

    @lru_cache
    def has_role_assignments(self, principal_id: str, principal_type: str) -> bool:
        try:
            res = self._find_single_object(
                f"""SELECT id FROM {self.schema}.principals_with_admin_roles
                    WHERE id = ? AND principal_type = ?""",
                [principal_id, principal_type],
            )
        except duckdb.CatalogException:
            return False

        return bool(res)

    @lru_cache
    def user_authentication_factors_count(self, user_id: str) -> int:
        if not self._table_exists("user_factors"):
            return 0

        row = self.client.execute(
            f"""SELECT COUNT(*) FROM {self.schema}.user_factors
                WHERE user_id = ?""",
            [user_id],
        ).fetchone()
        return int(row[0]) if row else 0

    @lru_cache
    def application_ids_by_name(self, app_name: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.applications WHERE name = ?""",
            [app_name],
        )
        return res

    @lru_cache
    def api_service_ids_by_name(self, app_name: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.api_services WHERE type = ?""",
            [app_name],
        )
        return res

    @lru_cache
    def application_secret_ids(self, app_id: str):
        secret_ids = set(self._ids_by_value("application_secrets", "app_id", app_id))
        secret_ids.update(self._ids_by_value("api_service_secrets", "app_id", app_id))
        return tuple((secret_id,) for secret_id in sorted(secret_ids))

    @lru_cache
    def application_oauth_scopes(self, app_id: str) -> tuple[str, ...]:
        try:
            rows = self._find_all_objects(
                f"""SELECT scope_id FROM {self.schema}.application_grants
                    WHERE app_id = ?
                      AND scope_id IS NOT NULL
                      AND TRIM(scope_id) <> ''""",
                [app_id],
            )
        except duckdb.CatalogException:
            return ()

        return tuple(scope_id for (scope_id,) in rows)

    @lru_cache
    def application_domain_sid(self, app_id: str) -> str | None:
        sid_queries = (
            f"""SELECT COALESCE(
                    json_extract_string(profile, '$.objectSid'),
                    json_extract_string(profile, '$.object_sid')
                )
                FROM {self.schema}.application_users
                WHERE app_id = ?
                  AND sync_state = 'SYNCHRONIZED'
                  AND COALESCE(
                    json_extract_string(profile, '$.objectSid'),
                    json_extract_string(profile, '$.object_sid')
                  ) IS NOT NULL
                LIMIT 1""",
            f"""SELECT COALESCE(
                    json_extract_string(profile, '$.objectSid'),
                    json_extract_string(profile, '$.object_sid')
                )
                FROM {self.schema}.groups
                WHERE COALESCE(
                    json_extract_string(source, '$.id'),
                    json_extract_string(source, '$.source_id')
                  ) = ?
                  AND COALESCE(
                    json_extract_string(profile, '$.objectSid'),
                    json_extract_string(profile, '$.object_sid')
                  ) IS NOT NULL
                LIMIT 1""",
        )
        for query in sid_queries:
            try:
                object_sid = self._find_single_object(query, [app_id])
            except duckdb.CatalogException:
                continue

            if object_sid and "-" in object_sid:
                return object_sid.rsplit("-", 1)[0]

        return None

    @lru_cache
    def resource_set_application_ids(self, resource_set_id: str):
        return self._resource_set_ids_in_table(resource_set_id, "applications")

    @lru_cache
    def resource_set_non_admin_application_ids(self, resource_set_id: str):
        resource_set_apps = set(self.resource_set_application_ids(resource_set_id))
        non_admin_apps = {app_id for (app_id,) in self.non_admin_apps()}
        return tuple(sorted(resource_set_apps & non_admin_apps))

    @lru_cache
    def resource_set_user_ids(self, resource_set_id: str):
        return self._resource_set_ids_in_table(resource_set_id, "users")

    @lru_cache
    def resource_set_non_admin_user_ids(self, resource_set_id: str):
        resource_set_users = set(self.resource_set_user_ids(resource_set_id))
        non_admin_users = {user_id for (user_id,) in self.non_admin_users()}
        return tuple(sorted(resource_set_users & non_admin_users))

    @lru_cache
    def resource_set_group_ids(self, resource_set_id: str):
        return self._resource_set_ids_in_table(resource_set_id, "groups")

    @lru_cache
    def resource_set_non_admin_group_ids(self, resource_set_id: str):
        resource_set_groups = set(self.resource_set_group_ids(resource_set_id))
        non_admin_groups = {group_id for (group_id,) in self.non_admin_groups()}
        return tuple(sorted(resource_set_groups & non_admin_groups))

    @lru_cache
    def group_user_ids(self, group_ids: tuple[str, ...]):
        user_ids: set[str] = set()
        for group_id in group_ids:
            rows = self._find_all_objects(
                f"""SELECT id FROM {self.schema}.group_memberships WHERE group_id = ?""",
                [group_id],
            )
            user_ids.update(user_id for (user_id,) in rows)
        return tuple(sorted(user_ids))

    @lru_cache
    def role_assignment_exists(self, role_assignment_id: str, assignee_id: str) -> bool:
        for table in (
            "user_role_assignments",
            "group_role_assignments",
            "client_role_assignments",
        ):
            try:
                result = self._find_single_object(
                    f"""SELECT id FROM {self.schema}.{table}
                        WHERE id = ? AND source_id = ?""",
                    [role_assignment_id, assignee_id],
                )
            except duckdb.CatalogException:
                continue

            if result:
                return True

        return False

    @lru_cache
    def role_assignment_resource_set_ids(
        self, role_assignment_id: str, assignee_id: str
    ) -> tuple[str, ...]:
        try:
            rows = self._find_all_objects(
                f"""SELECT resource_set_id FROM {self.schema}.resource_set_role_assignments
                    WHERE id = ? AND assignee_id = ?""",
                [role_assignment_id, assignee_id],
            )
        except duckdb.CatalogException:
            return ()

        return tuple(sorted({resource_set_id for (resource_set_id,) in rows}))

    @lru_cache
    def resource_set_member_ids(self, resource_set_id: str) -> tuple[str, ...]:
        try:
            rows = self._find_all_objects(
                f"""SELECT json_extract_string(_links, '$.self.href'), orn
                    FROM {self.schema}.resources
                    WHERE resource_set_id = ?""",
                [resource_set_id],
            )
        except duckdb.CatalogException:
            return ()

        resource_ids: set[str] = set()
        for resource_url, orn in rows:
            resolved_ids = (
                self.resolve_resource_url(resource_url)
                if resource_url
                else self.resolve_resource_orn(orn)
            )
            resource_ids.update(resolved_ids)
        return tuple(sorted(resource_ids))

    @lru_cache
    def resolve_resource_url(self, resource_url: str | None) -> tuple[str, ...]:
        """Resolve an Okta resource set member URL the same way OktaHound does."""
        if not resource_url:
            return ()

        parsed_url = urlparse(resource_url)
        path = parsed_url.path.rstrip("/") or "/"

        if path == "/api/v1/users":
            return self._all_ids("users")
        if path.startswith("/api/v1/users/"):
            return self._existing_ids("users", path.rsplit("/", 1)[-1])

        if path == "/api/v1/groups":
            return self._all_ids("groups")
        if path.startswith("/api/v1/groups/") and path.endswith("/users"):
            group_id = path.split("/")[-2]
            return self.group_user_ids((group_id,))
        if path.startswith("/api/v1/groups/"):
            return self._existing_ids("groups", path.rsplit("/", 1)[-1])

        if path == "/api/v1/apps":
            if not parsed_url.query:
                return self._all_apps_and_integrations()

            app_type = self._app_type_from_filter(parsed_url.query)
            if app_type:
                return self._apps_and_integrations_by_type(app_type)
            return ()
        if path.startswith("/api/v1/apps/"):
            app_id = path.rsplit("/", 1)[-1]
            return tuple(
                sorted(
                    set(self._existing_ids("applications", app_id))
                    | set(self._existing_ids("api_services", app_id))
                )
            )

        if path == "/api/v1/authorizationServers":
            return self._all_ids("authorization_servers")
        if path.startswith("/api/v1/authorizationServers/"):
            return self._existing_ids(
                "authorization_servers", path.rsplit("/", 1)[-1]
            )

        if path == "/api/v1/devices":
            return self._all_ids("devices")
        if path.startswith("/api/v1/devices/"):
            return self._existing_ids("devices", path.rsplit("/", 1)[-1])

        if path == "/api/v1/idps":
            return self._all_ids("identity_providers")
        if path.startswith("/api/v1/idps/"):
            return self._existing_ids(
                "identity_providers", path.rsplit("/", 1)[-1]
            )

        if path == "/api/v1/policies":
            return self._all_ids("policies")
        if path.startswith("/api/v1/policies/"):
            return self._existing_ids("policies", path.rsplit("/", 1)[-1])

        return ()

    @lru_cache
    def resolve_resource_orn(self, orn: str | None) -> tuple[str, ...]:
        """Fallback for older payloads that do not expose a self URL."""
        if not orn:
            return ()

        split_orn = orn.split(":")
        resource_collections = {
            "users": self._all_ids("users"),
            "groups": self._all_ids("groups"),
            "apps": self._all_apps_and_integrations(),
            "devices": self._all_ids("devices"),
            "authorizationServers": self._all_ids("authorization_servers"),
            "authorization_servers": self._all_ids("authorization_servers"),
            "idps": self._all_ids("identity_providers"),
            "policies": self._all_ids("policies"),
        }
        if split_orn[-1] in resource_collections:
            return resource_collections[split_orn[-1]]

        target_id = split_orn[-1]
        for resource_type, table_names in {
            "users": ("users",),
            "groups": ("groups",),
            "apps": ("applications", "api_services"),
            "devices": ("devices",),
            "authorizationServers": ("authorization_servers",),
            "authorization_servers": ("authorization_servers",),
            "idps": ("identity_providers",),
            "policies": ("policies",),
        }.items():
            if resource_type not in split_orn[:-1]:
                continue

            resource_ids: set[str] = set()
            for table_name in table_names:
                resource_ids.update(self._existing_ids(table_name, target_id))
            return tuple(sorted(resource_ids))
        return ()

    def _resource_set_ids_in_table(
        self, resource_set_id: str, table_name: str
    ) -> tuple[str, ...]:
        member_ids = set(self.resource_set_member_ids(resource_set_id))
        return tuple(sorted(member_ids & set(self._all_ids(table_name))))

    @lru_cache
    def _all_ids(self, table_name: str) -> tuple[str, ...]:
        if not self._table_exists(table_name):
            return ()
        if table_name == "devices":
            return self._device_graph_ids()
        rows = self._find_all_objects(f"""SELECT id FROM {self.schema}.{table_name}""")
        return tuple(sorted({resource_id for (resource_id,) in rows}))

    @lru_cache
    def _existing_ids(self, table_name: str, resource_id: str) -> tuple[str, ...]:
        if not self._table_exists(table_name):
            return ()
        if table_name == "devices":
            graph_id = self.device_graph_id_by_okta_id(resource_id)
            return (graph_id,) if graph_id else ()
        rows = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.{table_name} WHERE id = ?""",
            [resource_id],
        )
        return tuple(sorted({row_id for (row_id,) in rows}))

    @lru_cache
    def _ids_by_value(
        self, table_name: str, column_name: str, value: str
    ) -> tuple[str, ...]:
        if not self._table_exists(table_name):
            return ()
        rows = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.{table_name} WHERE {column_name} = ?""",
            [value],
        )
        return tuple(sorted({resource_id for (resource_id,) in rows}))

    @lru_cache
    def _all_apps_and_integrations(self) -> tuple[str, ...]:
        return tuple(
            sorted(set(self._all_ids("applications")) | set(self._all_ids("api_services")))
        )

    @lru_cache
    def _apps_and_integrations_by_type(self, app_type: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                set(self._ids_by_value("applications", "name", app_type))
                | set(self._ids_by_value("api_services", "type", app_type))
            )
        )

    @staticmethod
    def _app_type_from_filter(query: str) -> str | None:
        filter_value = parse_qs(query).get("filter", [None])[0]
        if not filter_value:
            return None

        match = re.fullmatch(r'name eq "([^"]+)"', filter_value)
        return match.group(1) if match else None

    @lru_cache
    def all_policies(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.policies""")
        return res

    @lru_cache
    def all_identity_providers(self):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.identity_providers"""
        )
        return res

    @lru_cache
    def all_auth_servers(self):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.authorization_servers"""
        )
        return res

    @lru_cache
    def all_devices(self):
        return tuple((device_id,) for device_id in self._device_graph_ids())

    @lru_cache
    def _device_graph_ids(self) -> tuple[str, ...]:
        if not self._table_exists("devices"):
            return ()

        profile_expr = (
            "json_extract_string(profile, '$.udid')"
            if self._column_exists("devices", "profile")
            else "NULL"
        )
        rows = self._find_all_objects(
            f"""SELECT id, {profile_expr} FROM {self.schema}.devices"""
        )
        return tuple(
            sorted(
                {
                    self._device_graph_id(okta_device_id, udid)
                    for okta_device_id, udid in rows
                }
            )
        )

    @lru_cache
    def device_graph_id_by_okta_id(self, okta_device_id: str) -> str | None:
        if not self._table_exists("devices"):
            return None

        profile_expr = (
            "json_extract_string(profile, '$.udid')"
            if self._column_exists("devices", "profile")
            else "NULL"
        )
        rows = self._find_all_objects(
            f"""SELECT id, {profile_expr} FROM {self.schema}.devices WHERE id = ?""",
            [okta_device_id],
        )
        if not rows:
            return None

        device_id, udid = rows[0]
        return self._device_graph_id(device_id, udid)

    def _device_graph_id(self, okta_device_id: str, udid: str | None) -> str:
        from openhound_okta.models.device import device_graph_id

        return device_graph_id(okta_device_id, udid, self.tenant_domain)

    @lru_cache
    def manager_id(self, manager_login: str):
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.users WHERE json_extract_string(profile, '$.login') = ?""",
            [manager_login],
        )
        return res
