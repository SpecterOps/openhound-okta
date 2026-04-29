from functools import lru_cache

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
    def all_api_services(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.api_services""")
        return res

    @lru_cache
    def all_applications(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.applications""")
        return res

    @lru_cache
    def application_ids_by_name(self, app_name: str):
        res = self._find_all_objects(
            f"""SELECT id FROM {self.schema}.applications WHERE name = ?""",
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
    def resource_set_application_ids(self, resource_set_id: str):
        return self._resource_set_resource_ids(
            resource_set_id, "apps", self.all_applications()
        )

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
