import duckdb

from openhound_okta.lookup import OktaLookup
from openhound_okta.kinds import edges as ek
from openhound_okta.models import Device
from openhound_okta.models.device import device_graph_id


class StubLookup:
    def org_id(self):
        return "org-1"


def make_device() -> Device:
    device = Device.model_validate(
        {
            "id": "okta-device-1",
            "status": "ACTIVE",
            "created": "2026-01-01T00:00:00Z",
            "lastUpdated": "2026-01-02T00:00:00Z",
            "profile": {
                "displayName": "DESKTOP-01",
                "platform": "WINDOWS",
                "manufacturer": "Dell Inc.",
                "model": "XPS 14",
                "osVersion": "10.0.1",
                "registered": True,
                "secureHardwarePresent": True,
                "integrityJailbreak": False,
                "udid": "hardware-uuid-1",
                "sid": "S-1-5-21-1",
                "serialNumber": "SERIAL-1",
            },
            "resourceType": "UDDevice",
            "resourceId": "okta-device-1",
        }
    )
    device._lookup = StubLookup()
    device._extras = {"tenant": "example.okta.com"}
    return device


def test_device_node_emits_oktahound_equivalent_properties():
    device = make_device()

    properties = device.as_node.properties

    assert properties.id == "hardware-uuid-1@example.okta.com"
    assert properties.okta_domain == "example.okta.com"
    assert properties.okta_id == "okta-device-1"
    assert properties.secure_hardware_present is True
    assert properties.jail_break is False
    assert properties.udid == "hardware-uuid-1"
    assert properties.object_sid == "S-1-5-21-1"
    assert properties.serial_number == "SERIAL-1"
    assert not hasattr(properties, "resource_id")


def test_device_graph_ids_use_udid_when_available():
    assert (
        device_graph_id("okta-device-1", "hardware-uuid-1", "example.okta.com")
        == "hardware-uuid-1@example.okta.com"
    )
    assert (
        device_graph_id("okta-device-1", None, "example.okta.com")
        == "okta-device-1"
    )


def test_device_edges_use_graph_id():
    device = make_device()

    contains = next(edge for edge in device.edges if edge.kind == ek.CONTAINS)

    assert contains.end.value == "hardware-uuid-1@example.okta.com"


def test_device_lookups_return_graph_ids_for_device_targets():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.devices (id VARCHAR, profile JSON)")
    con.execute(
        "INSERT INTO okta.devices VALUES "
        "('okta-device-1', '{\"udid\":\"hardware-uuid-1\"}'), "
        "('okta-device-2', '{}')"
    )
    lookup = OktaLookup(con)
    lookup.tenant_domain = "example.okta.com"

    assert lookup.all_devices() == (
        ("hardware-uuid-1@example.okta.com",),
        ("okta-device-2",),
    )
    assert lookup.resolve_resource_url("https://example.okta.com/api/v1/devices") == (
        "hardware-uuid-1@example.okta.com",
        "okta-device-2",
    )
    assert lookup.resolve_resource_url(
        "https://example.okta.com/api/v1/devices/okta-device-1"
    ) == ("hardware-uuid-1@example.okta.com",)
