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
    def application_exists(self, app_id: str) -> bool:
        res = self._find_single_object(
            f"""SELECT id FROM {self.schema}.applications WHERE id = ?""",
            [app_id],
        )
        return res

    @lru_cache
    def all_groups(self):
        res = self._find_all_objects(f"""SELECT id FROM {self.schema}.groups""")
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
        rows = self._find_all_objects(
            f"""SELECT orn FROM {self.schema}.resources WHERE resource_set_id = ? AND contains(orn, ':apps')""",
            [resource_set_id],
        )
        application_ids: set[str] = set()
        # TODO: Implement a resource on the test tenant
        # when the test tenant contains a valid edge based on a
        # custom role, add the conditions to return app ids here.
        return application_ids

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
