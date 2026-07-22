from openhound_okta.kinds import edges as ek
from openhound_okta.models import ApplicationGroupMapping


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
