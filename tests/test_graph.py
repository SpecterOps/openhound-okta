from dataclasses import dataclass

from openhound.core.models.entries_dataclass import (
    EdgePath as BaseEdgePath,
)

from openhound_okta.graph import OktaNode, OktaNodeProperties, OktaOwnedEdgePath


@dataclass
class _StubProperties(OktaNodeProperties):
    """Minimal concrete properties subclass for exercising OktaNodeProperties."""


def _make_properties(**overrides) -> _StubProperties:
    fields = {
        "name": "alice@example.com",
        "displayname": "Alice Example",
        "environmentid": "org-1",
        "tenant": "org-1",
        "tenant_domain": "example.okta.com",
        "id": "user-1",
        **overrides,
    }
    return _StubProperties(**fields)


def test_okta_node_properties_uppercases_name():
    properties = _make_properties(name="alice@example.com")

    assert properties.name == "ALICE@EXAMPLE.COM"


def test_okta_node_properties_does_not_uppercase_displayname():
    properties = _make_properties(displayname="Alice Example")

    assert properties.displayname == "Alice Example"


def test_okta_node_properties_uppercases_environmentid():
    properties = _make_properties(environmentid="mixedCase-Org-1")

    assert properties.environmentid == "MIXEDCASE-ORG-1"


def test_okta_node_properties_does_not_uppercase_tenant():
    properties = _make_properties(tenant="mixedCase-Org-1")

    assert properties.tenant == "mixedCase-Org-1"


def test_okta_node_uppercases_id():
    properties = _make_properties(id="mixedCase-Id-1")

    node = OktaNode(kinds=["Okta_User"], properties=properties)

    assert node.id == "MIXEDCASE-ID-1"


def test_okta_owned_edge_path_uppercases_value_when_matching_by_id():
    edge = OktaOwnedEdgePath(value="mixedCase-Id-1", match_by="id")

    assert edge.value == "MIXEDCASE-ID-1"


def test_okta_owned_edge_path_leaves_value_unchanged_for_other_match_by():
    edge = OktaOwnedEdgePath(value="mixedCase-Value", match_by="property")

    assert edge.value == "mixedCase-Value"


def test_okta_owned_edge_path_is_subclass_of_shared_edge_path():
    edge = OktaOwnedEdgePath(value="abc", match_by="id")

    assert isinstance(edge, BaseEdgePath)


def test_shared_edge_path_is_unaffected_by_okta_owned_edge_path():
    """The shared openhound.core.EdgePath must not uppercase values.

    Cross-collector edge construction (e.g. hybrid_auth.py) imports the
    shared EdgePath directly, not OktaOwnedEdgePath, since other
    collectors' node ids have their own casing rules.
    """
    shared_edge = BaseEdgePath(value="mixedCase-Id-1", match_by="id")

    assert shared_edge.value == "mixedCase-Id-1"
