from openhound_okta.models import Organization


class StubLookup:
    def org_id(self):
        return "org-1"


def make_organization(**overrides):
    organization = Organization.model_validate(
        {
            "id": "org-1",
            "subdomain": "example",
            "status": "ACTIVE",
            "created": "2026-01-01T00:00:00Z",
            "lastUpdated": "2026-01-02T00:00:00Z",
            "companyName": "Example Corp",
            "website": "https://example.com",
            **overrides,
        }
    )
    organization._lookup = StubLookup()
    organization._extras = {"tenant": "example.okta.com"}
    return organization


def test_organization_node_emits_oktahound_equivalent_properties():
    organization = make_organization()

    properties = organization.as_node.properties

    assert properties.name == "EXAMPLE.OKTA.COM"
    assert properties.displayname == "Example Corp"
    assert properties.okta_domain == "example.okta.com"
    assert properties.subdomain == "example"
    assert properties.status == "ACTIVE"
    assert properties.collected is True
    assert not hasattr(properties, "company_name")
    assert not hasattr(properties, "website")


def test_organization_node_falls_back_to_subdomain_for_display_name():
    organization = make_organization(companyName=None)

    assert organization.as_node.properties.displayname == "example"
