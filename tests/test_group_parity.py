from openhound_okta.kinds import edges as ek
from openhound_okta.models import Group


class StubLookup:
    def __init__(self, *, has_role_assignments: bool = False):
        self._has_role_assignments = has_role_assignments

    def org_id(self):
        return "org-1"

    def has_role_assignments(self, principal_id, principal_type):
        assert principal_id == "group-1"
        assert principal_type == "group"
        return self._has_role_assignments

    def application_by_id(self, app_id):
        return app_id == "app-1"

    def application_settings(self, app_id):
        assert app_id == "app-1"
        return '{"app":{"baseUrl":"https://source.example.okta.com"}}'

    def application_name(self, app_id):
        assert app_id == "app-1"
        return "okta_org2org"


def make_group(*, has_role_assignments: bool = False, **overrides):
    group = Group.model_validate(
        {
            "id": "group-1",
            "created": "2026-01-01T00:00:00Z",
            "type": "OKTA_GROUP",
            "lastUpdated": "2026-01-02T00:00:00Z",
            "lastMembershipUpdated": "2026-01-03T00:00:00Z",
            "objectClass": ["okta:user_group"],
            "profile": {
                "name": "Engineering",
                "description": "Engineering users",
            },
            "_embedded": {
                "stats": {
                    "usersCount": 3,
                    "appsCount": 1,
                    "hasAdminPrivilege": False,
                }
            },
            **overrides,
        }
    )
    group._lookup = StubLookup(has_role_assignments=has_role_assignments)
    group._extras = {"tenant": "example.okta.com"}
    return group


def test_group_node_emits_core_oktahound_equivalent_properties():
    group = make_group(has_role_assignments=True)

    properties = group.as_node.properties

    assert properties.name == "Engineering"
    assert properties.displayname == "Engineering"
    assert properties.okta_domain == "example.okta.com"
    assert properties.okta_group_type == "OKTA_GROUP"
    assert properties.object_class == "okta:user_group"
    assert properties.description == "Engineering users"
    assert properties.has_role_assignments is True
    assert not hasattr(properties, "type")


def test_group_node_emits_active_directory_profile_properties():
    group = make_group(
        type="APP_GROUP",
        objectClass=["okta:windows_security_principal"],
        profile={
            "name": "ADSyncAdmins",
            "description": "AD group",
            "windowsDomainQualifiedName": "CORP\\ADSyncAdmins",
            "dn": "CN=ADSyncAdmins,CN=Users,DC=corp,DC=example,DC=com",
            "externalId": "reHMVHhyo0yxRhnsb5DTSg==",
            "samAccountName": "ADSyncAdmins",
            "objectSid": "S-1-5-21-111-222-333-1001",
            "groupScope": "Domain Local",
            "groupType": "Security",
        },
    )

    properties = group.as_node.properties

    assert properties.object_sid == "S-1-5-21-111-222-333-1001"
    assert (
        properties.distinguished_name
        == "CN=ADSyncAdmins,CN=Users,DC=corp,DC=example,DC=com"
    )
    assert properties.sam_account_name == "ADSyncAdmins"
    assert properties.domain_qualified_name == "CORP\\ADSyncAdmins"
    assert properties.group_scope == "Domain Local"
    assert properties.group_type == "Security"
    assert properties.object_guid == "54cce1ad-7278-4ca3-b146-19ec6f90d34a"


def test_group_membership_sync_matcher_uses_oktahound_name_and_domain_name():
    group = make_group(
        type="APP_GROUP",
        source={"id": "app-1"},
    )

    edge = next(edge for edge in group.edges if edge.kind == ek.MEMBERSHIP_SYNC)
    matchers = {matcher.key: matcher.value for matcher in edge.start.property_matchers}

    assert matchers == {
        "name": "Engineering",
        "domainName": "source.example.okta.com",
    }
