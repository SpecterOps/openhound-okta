from openhound_okta.models import Application


class StubLookup:
    def org_id(self):
        return "org-1"


def make_application(*, name: str = "githubcloud", label: str = "GitHub Enterprise Cloud"):
    application = Application.model_validate(
        {
            "id": "app-1",
            "orn": "orn:okta:idp:example:apps:app-1",
            "name": name,
            "label": label,
            "status": "ACTIVE",
            "created": "2026-01-01T00:00:00Z",
        }
    )
    application._lookup = StubLookup()
    application._extras = {"tenant": "example.okta.com"}
    return application


def test_application_node_uses_label_for_name_and_preserves_raw_app_type():
    application = make_application()

    properties = application.as_node.properties

    assert properties.name == "GitHub Enterprise Cloud"
    assert properties.displayname == "GitHub Enterprise Cloud"
    assert properties.app_type == "githubcloud"
    assert properties.label == "GitHub Enterprise Cloud"


def test_application_node_falls_back_to_raw_app_type_when_label_is_empty():
    application = make_application(name="active_directory", label="")

    properties = application.as_node.properties

    assert properties.name == "active_directory"
    assert properties.displayname == "active_directory"
    assert properties.app_type == "active_directory"
