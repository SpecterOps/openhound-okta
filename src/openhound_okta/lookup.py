from functools import lru_cache

import duckdb
from duckdb import DuckDBPyConnection
from openhound.core.lookup import LookupManager


class OktaLookup(LookupManager):
    def __init__(self, client: DuckDBPyConnection, schema: str = "okta"):
        super().__init__(client, schema)
        self.schema = schema
        self.client = client

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
    def application_settings(self, app_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT settings FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def all_groups(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.groups""")
        return res

    @lru_cache
    def non_admin_groups(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.non_admin_groups""")
        return res

    @lru_cache
    def all_users(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.users""")
        return res

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
    def application_ids_by_name(self, app_name: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.applications WHERE name = ?""",
            [app_name],
        )
        return res

    @lru_cache
    def api_service_ids_by_name(self, app_name: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.api_services WHERE name = ?""",
            [app_name],
        )
        return res

    @lru_cache
    def application_secret_ids(self, app_id: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.application_secrets WHERE app_id = ?""",
            [app_id],
        )
        return res

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
        return self._resource_set_resource_ids(
            resource_set_id, "apps", self.all_applications()
        )

    @lru_cache
    def resource_set_non_admin_application_ids(self, resource_set_id: str):
        resource_set_apps = set(self.resource_set_application_ids(resource_set_id))
        non_admin_apps = {app_id for (app_id,) in self.non_admin_apps()}
        return tuple(sorted(resource_set_apps & non_admin_apps))

    @lru_cache
    def resource_set_user_ids(self, resource_set_id: str):
        return self._resource_set_resource_ids(
            resource_set_id, "users", self.all_users()
        )

    @lru_cache
    def resource_set_non_admin_user_ids(self, resource_set_id: str):
        resource_set_users = set(self.resource_set_user_ids(resource_set_id))
        non_admin_users = {user_id for (user_id,) in self.non_admin_users()}
        return tuple(sorted(resource_set_users & non_admin_users))

    @lru_cache
    def resource_set_group_ids(self, resource_set_id: str):
        return self._resource_set_resource_ids(
            resource_set_id, "groups", self.all_groups()
        )

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

    def _resource_set_resource_ids(
        self, resource_set_id: str, resource_type: str, all_resource_rows
    ):
        rows = self._find_all_objects(
            f"""SELECT orn FROM {self.schema}.resources WHERE resource_set_id = ? AND contains(orn, ?)""",
            [resource_set_id, f":{resource_type}"],
        )

        resource_ids: set[str] = set()
        for (orn,) in rows:
            split_orn = orn.split(":")
            if len(split_orn) == 5 and split_orn[-1] == resource_type:
                resource_ids.update(resource_id for (resource_id,) in all_resource_rows)
            elif len(split_orn) == 6 and split_orn[-2] == resource_type:
                resource_ids.add(split_orn[-1])
        return tuple(sorted(resource_ids))

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
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.devices""")
        return res

    @lru_cache
    def manager_id(self, manager_login: str):
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.users WHERE json_extract_string(profile, '$.login') = ?""",
            [manager_login],
        )
        return res
