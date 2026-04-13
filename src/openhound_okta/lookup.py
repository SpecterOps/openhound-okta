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
        return res is not None

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
            f"""SELECT id, json_value(profile, 'login') AS login FROM {self.schema}.users WHERE login = ?""",
            [manager_login],
        )
        return res

    # @lru_cache
    # def group_member_ids(self, group_id: str):
    #     res = self._find_all_objects(
    #         f"""SELECT id FROM {self.schema}.group_memberships WHERE group_id = ?""",
    #         [group_id]
    #     return res
