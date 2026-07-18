from datetime import datetime

from openhound.core.asset import BaseAsset, EdgeDef
from openhound.core.models.entries_dataclass import Edge, EdgePath, EdgeProperties
from pydantic import BaseModel, ConfigDict, Field

from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.main import app
from openhound_okta.models.saml import (
    SamlAccountEdgeProperties,
    saml_idp_user_identity_evidence,
    saml_match_source,
    saml_service_provider_id,
)


class Profile(BaseModel):
    last_name: str | None = Field(alias="lastName", default=None)
    first_name: str | None = Field(alias="firstName", default=None)
    email: str | None = None
    ms_object_identifier: str | None = Field(
        alias="msObjectIdentifier",
        default=None,
    )
    subject_name_id: str | None = Field(alias="subjectNameId", default=None)
    subject_name_qualifier: str | None = Field(
        alias="subjectNameQualifier",
        default=None,
    )
    subject_sp_name_qualifier: str | None = Field(
        alias="subjectSpNameQualifier",
        default=None,
    )


@app.asset(
    description="Okta identity provider asset",
    edges=[
        EdgeDef(
            start=nk.IDP,
            end=nk.USER,
            kind=ek.IDENTITY_PROVIDER_FOR,
            description="Identity provider manages user",
            traversable=True,
        ),
        EdgeDef(
            start=nk.ORG,
            end=nk.USER,
            kind=ek.INBOUND_SSO,
            description="User identity via SSO",
            traversable=True,
        ),
        EdgeDef(
            start=nk.SAML_SERVICE_PROVIDER,
            end=nk.USER,
            kind=ek.SAML_HAS_ACCOUNT,
            description="SAML service provider can map assertions to an Okta user account",
            traversable=False,
        ),
    ],
)
class IDPUser(BaseAsset):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    external_id: str | None = Field(alias="externalId", default=None)
    created: datetime | None = None
    last_updated: datetime | None = Field(alias="lastUpdated", default=None)
    profile: Profile | None = None

    # Additional
    idp_id: str
    idp_type: str
    idp_name: str
    idp_status: str | None = None
    idp_url: str | None = None
    idp_subject_user_name_template: str | None = None
    idp_subject_match_type: str | None = None
    idp_subject_filter: str | None = None

    @property
    def as_node(self):
        return None

    @property
    def _inbound_sso_edge(self):
        entra_object_id = (
            self.profile.ms_object_identifier if self.profile else None
        )
        if (
            self.idp_type == "SAML2"
            and self.idp_url
            and "microsoftonline.com" in self.idp_url
            and entra_object_id
        ):
            yield Edge(
                kind=ek.INBOUND_SSO,
                start=EdgePath(value=entra_object_id, match_by="id"),
                end=EdgePath(value=self.id, match_by="id"),
                properties=EdgeProperties(traversable=True),
            )

    @property
    def _identity_provider_for_edge(self):
        yield Edge(
            kind=ek.IDENTITY_PROVIDER_FOR,
            start=EdgePath(value=self.idp_id, match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=EdgeProperties(traversable=True),
        )

    @property
    def _saml_has_account_edge(self):
        if self.idp_type != "SAML2":
            return
        if self.idp_status and self.idp_status != "ACTIVE":
            return

        evidence = saml_idp_user_identity_evidence(self)
        if not evidence["match_values"]:
            return
        yield Edge(
            kind=ek.SAML_HAS_ACCOUNT,
            start=EdgePath(value=saml_service_provider_id(self.idp_id), match_by="id"),
            end=EdgePath(value=self.id, match_by="id"),
            properties=SamlAccountEdgeProperties(
                traversable=False,
                match_values=evidence["match_values"],
                email_match_values=evidence["email_match_values"],
                entra_object_id_match_values=evidence[
                    "entra_object_id_match_values"
                ],
                scoped_exact_match_values=evidence[
                    "scoped_exact_match_values"
                ],
                source_property=saml_match_source(self.idp_subject_user_name_template),
                account_state="unknown",
                direct_binding=True,
                direct_binding_source="GET /api/v1/idps/{idpId}/users",
            ),
        )

    @property
    def edges(self):
        yield from self._identity_provider_for_edge
        yield from self._inbound_sso_edge
        yield from self._saml_has_account_edge
