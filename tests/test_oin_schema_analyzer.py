import json
from pathlib import Path
from typing import Any

import pytest

from tools.oin_lab.lab import (
    LabSafetyError,
    REPOSITORY_ROOT,
    analyze_catalog_schema_file,
    main,
)
from tools.oin_lab.schema_analyzer import (
    SchemaAnalysisError,
    analyze_catalog_schema_snapshot,
)


def _application(
    app_key: str,
    definitions: dict[str, Any] | None,
) -> dict[str, Any]:
    application: dict[str, Any] = {
        "name": app_key,
        "displayName": app_key.replace("_", " ").title(),
        "signOnModes": ["SAML_2_0"],
    }
    if definitions is not None:
        application["_embedded"] = {"schema": {"definitions": definitions}}
    return application


def _snapshot(applications: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "captured_at": "2026-08-14T00:00:00+00:00",
        "source": "Okta Catalog API test fixture",
        "applications": applications,
    }


def test_analyzer_inventories_every_definition_and_classifies_route_signals():
    snapshot = _snapshot(
        [
            _application(
                "template_app",
                {
                    "general": {
                        "properties": {
                            "region": {
                                "title": "Region",
                                "type": "string",
                                "enum": ["us", "eu"],
                            },
                            "siteUrl": {
                                "title": "Site URL",
                                "description": (
                                    "For an ACS URL like "
                                    "https://acme.example.test/saml/acs, enter the site URL."
                                ),
                                "format": "uri",
                                "type": "string",
                            },
                            "scimBaseUrl": {
                                "title": "SCIM Base URL",
                                "type": "string",
                            },
                        }
                    },
                    "hidden": {"properties": {"opaqueFlag": {"type": "boolean"}}},
                },
            ),
            _application(
                "default_app",
                {
                    "sso": {
                        "properties": {
                            "customAcsUrl": {
                                "title": "Custom ACS URL",
                                "description": (
                                    "<p>The default one is "
                                    "https://example.test/sso/saml.</p>"
                                ),
                                "type": "string",
                            }
                        }
                    }
                },
            ),
            _application(
                "required_app",
                {
                    "sso": {
                        "required": ["acsURL"],
                        "properties": {
                            "acsURL": {
                                "title": "ACS URL",
                                "type": "string",
                            },
                            "entityID": {
                                "title": "Entity ID",
                                "required": True,
                                "type": "string",
                            },
                        },
                    }
                },
            ),
            _application(
                "unknown_app",
                {
                    "general": {
                        "properties": {
                            "loginURL": {
                                "description": (
                                    "The default login URL is "
                                    "https://example.test/dashboard."
                                )
                            }
                        }
                    }
                },
            ),
        ]
    )

    analysis = analyze_catalog_schema_snapshot(snapshot)

    assert [item["app_key"] for item in analysis["applications"]] == [
        "default_app",
        "required_app",
        "template_app",
        "unknown_app",
    ]
    by_key = {item["app_key"]: item for item in analysis["applications"]}
    assert by_key["default_app"]["attributes"][0]["description"] == (
        "The default one is https://example.test/sso/saml."
    )
    assert by_key["default_app"]["classification"] == {
        "route_signals": ["explicit_route_input", "catalog_default_hint"],
        "research_disposition": "catalog_default_review",
        "authoritative_route": False,
        "requires_human_review": True,
    }
    assert by_key["required_app"]["classification"]["research_disposition"] == (
        "required_explicit_route_review"
    )
    assert all(
        attribute["required"] for attribute in by_key["required_app"]["attributes"]
    )
    assert by_key["template_app"]["classification"]["route_signals"] == [
        "route_origin_input",
        "route_discriminator",
        "route_template_hint",
    ]
    assert by_key["template_app"]["classification"]["research_disposition"] == (
        "route_template_research"
    )
    assert (
        next(
            attribute
            for attribute in by_key["template_app"]["attributes"]
            if attribute["name"] == "scimBaseUrl"
        )["route_signals"]
        == []
    )
    assert by_key["unknown_app"]["classification"]["research_disposition"] == (
        "targeted_research"
    )
    assert by_key["unknown_app"]["attributes"][0]["route_signals"] == []
    assert analysis["applications_by_route_signal"] == {
        "explicit_route_input": 2,
        "route_origin_input": 1,
        "route_discriminator": 1,
        "route_template_hint": 1,
        "catalog_default_hint": 1,
    }


def test_analyzer_omits_sensitive_attributes_and_preserves_nonsecret_defaults():
    analysis = analyze_catalog_schema_snapshot(
        _snapshot(
            [
                _application(
                    "safe_app",
                    {
                        "general": {
                            "required": ["apiToken"],
                            "properties": {
                                "apiToken": {
                                    "description": "never-copy-this-secret-guidance",
                                    "default": "secret-value",
                                },
                                "accessKey": {
                                    "description": "also-sensitive",
                                    "default": "access-key-value",
                                    "required": True,
                                },
                                "environment": {
                                    "default": "production",
                                    "enum": ["production", "sandbox"],
                                    "type": "string",
                                },
                            }
                        }
                    },
                )
            ]
        )
    )

    application = analysis["applications"][0]
    assert application["omitted_sensitive_attribute_count"] == 2
    assert application["omitted_required_sensitive_attribute_names"] == [
        "accessKey",
        "apiToken",
    ]
    assert application["attributes"] == [
        {
            "section": "general",
            "name": "environment",
            "title": None,
            "description": None,
            "type": "string",
            "format": None,
            "required": False,
            "enum": ["production", "sandbox"],
            "has_default": True,
            "default": "production",
            "mutability": None,
            "scope": None,
            "route_signals": ["route_discriminator"],
        }
    ]
    assert "secret-value" not in json.dumps(analysis)
    assert "access-key-value" not in json.dumps(analysis)
    assert analysis["omitted_sensitive_attribute_count"] == 2


def test_analyzer_records_missing_definitions_without_inventing_attributes():
    analysis = analyze_catalog_schema_snapshot(
        _snapshot([_application("missing_schema", None)])
    )

    application = analysis["applications"][0]
    assert application["attributes"] == []
    assert application["diagnostics"] == ["missing_catalog_schema_definitions"]
    assert analysis["applications_with_diagnostics"] == 1


@pytest.mark.parametrize(
    "applications, message",
    [
        ([{"name": "invalid/key"}], "invalid app key"),
        ([{"name": "duplicate"}, {"name": "duplicate"}], "duplicate"),
    ],
)
def test_analyzer_rejects_ambiguous_application_identity(
    applications: list[dict[str, Any]], message: str
):
    with pytest.raises(SchemaAnalysisError, match=message):
        analyze_catalog_schema_snapshot(_snapshot(applications))


def test_analyze_schemas_cli_is_offline_deterministic_and_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    input_path = tmp_path / "applications.json"
    output_path = tmp_path / "inventory" / "schema-analysis.json"
    input_path.write_text(
        json.dumps(
            _snapshot(
                [
                    _application(
                        "example_app",
                        {"general": {"properties": {"domain": {"type": "string"}}}},
                    )
                ]
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("OKTA_API_TOKEN", raising=False)

    result = main(
        [
            "--matrix",
            str(tmp_path / "does-not-exist.sql"),
            "analyze-schemas",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ]
    )

    assert result == 0
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result["application_count"] == 1
    assert cli_result["attribute_count"] == 1
    assert output_path.stat().st_mode & 0o777 == 0o600
    first = output_path.read_text(encoding="utf-8")

    assert (
        main(
            [
                "--matrix",
                str(tmp_path / "still-does-not-exist.sql"),
                "analyze-schemas",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert output_path.read_text(encoding="utf-8") == first


def test_analyzer_refuses_to_write_output_inside_repository(tmp_path: Path):
    input_path = tmp_path / "applications.json"
    input_path.write_text(json.dumps(_snapshot([])), encoding="utf-8")

    with pytest.raises(LabSafetyError, match="outside the repository workspace"):
        analyze_catalog_schema_file(
            input_path, REPOSITORY_ROOT / "schema-analysis.json"
        )
