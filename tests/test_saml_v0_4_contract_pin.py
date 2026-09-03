import json
from pathlib import Path

from openhound_okta.models.saml import EMAIL_NAME_ID_FORMAT, saml_claim_projection
from openhound_okta.saml_eligibility import (
    SAML_GROUP_ELIGIBILITY_PROFILE,
    SAML_V0_4_CONTRACT_VERSION,
)


CONTRACT_PIN = Path(__file__).parent / "test_data" / "saml" / "v0_4_contract_pin.json"


def test_v0_4_producer_pin_matches_the_registered_projection_fixture():
    pin = json.loads(CONTRACT_PIN.read_text(encoding="utf-8"))

    assert pin["consumer"]["repository"] == "SpecterOps/openhound_saml"
    assert len(pin["consumer"]["revision"]) == 40
    assert pin["contract"]["id"] == SAML_V0_4_CONTRACT_VERSION
    assert pin["profile"] == SAML_GROUP_ELIGIBILITY_PROFILE
    assert set(pin["contract"]["artifacts"]) == {
        "contract.json",
        "registry.json",
        "identity-vectors.json",
        "normalized-fact.schema.json",
        "openhound_okta_group_membership_v1.json",
        "claim-projection-tuples.json",
        "contract-vectors.json",
        "observable-output-examples.json",
    }
    assert all(
        len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
        for digest in pin["contract"]["artifacts"].values()
    )

    projection = saml_claim_projection(
        source_property=pin["projection"]["source"],
        expression="${source.login}",
        claim_type="name_id",
        name_id_format=EMAIL_NAME_ID_FORMAT,
    )

    assert projection == {
        "principal_value_projection_profile": pin["projection"]["profile"],
        "principal_value_source_type": "native_principal_property",
        "projection_source": pin["projection"]["source"],
        "principal_node_property": pin["projection"]["property"],
        "projection_predicate": pin["projection"]["predicate"],
        "projected_match_value_field": pin["projection"]["output"],
        "projection_normalization_profile": pin["projection"]["normalizer"],
        "projection_scope": pin["projection"]["scope"],
        "projection_complete": True,
    }
