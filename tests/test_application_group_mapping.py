from openhound.core.models.entries_dataclass import ConditionalEdgePath

from openhound_okta.kinds import edges as ek
from openhound_okta.models import ApplicationGroupMapping


class StubLookup:
    def application_settings(self, app_id):
        assert app_id == "app-1"
        return '{"app":{"baseUrl":"https://target.example.okta.com/"}}'


def test_group_push_edges_start_from_source_group_and_end_at_application():
    mapping = ApplicationGroupMapping.model_validate(
        {
            "id": "mapping-1",
            "sourceGroupId": "source-group-1",
            "targetGroupId": "target-group-1",
            "app_id": "app-1",
            "app_name": "okta_org2org",
        }
    )

    edge = next(mapping.edges)

    assert edge.kind == ek.GROUP_PUSH
    assert edge.start.value == "source-group-1"
    assert edge.end.value == "app-1"


def test_group_push_mapping_emits_outbound_membership_sync_edge():
    mapping = ApplicationGroupMapping.model_validate(
        {
            "id": "mapping-1",
            "sourceGroupId": "source-group-1",
            "targetGroupId": "target-group-1",
            "target_group_name": "Engineering",
            "app_id": "app-1",
            "app_name": "okta_org2org",
        }
    )
    mapping._lookup = StubLookup()

    edge = next(edge for edge in mapping.edges if edge.kind == ek.MEMBERSHIP_SYNC)

    assert edge.start.value == "source-group-1"
    assert isinstance(edge.end, ConditionalEdgePath)
    assert {matcher.key: matcher.value for matcher in edge.end.property_matchers} == {
        "name": "Engineering",
        "domainName": "target.example.okta.com",
    }
