"""Okta collector credentials and request authentication."""

from base64 import b64decode
from typing import Union

import dlt
from dlt.common.configuration import configspec
from dlt.common.configuration.specs import CredentialsConfiguration
from dlt.common.typing import TSecretStrValue
from dlt.sources.helpers.rest_client.auth import APIKeyAuth

from .models.token import Token
from .utils.auth import OktaAuth, OktaBearerAuth

OKTA_DEFAULT_SCOPE = [
    "okta.users.read",
    "okta.apps.read",
    "okta.groups.read",
    "okta.roles.read",
    "okta.agentPools.read",
    "okta.apiTokens.read",
    "okta.authorizationServers.read",
    "okta.devices.read",
    "okta.policies.read",
    "okta.orgs.read",
    "okta.idps.read",
    "okta.features.read",
    "okta.clients.read",
    "okta.appGrants.read",
    "okta.oauthIntegrations.read",
    "okta.authenticators.read",
    # Optional scopes which require a dedicated license
    "okta.realms.read",
    "okta.realmAssignments.read",
]


@configspec
class OktaCredentials(CredentialsConfiguration):
    base_url: str = dlt.config.value

    def auth(self):
        pass


def _app_token(okta_auth: OktaAuth, base_url: str, client_id: str) -> Token:
    private_key = okta_auth.private_key
    jwt = okta_auth.jwt(
        private_key=private_key,
        client_id=client_id,
        audience=f"{base_url}/oauth2/v1/token",
        exp_delta=60,
    )
    return okta_auth.token_response(base_url, jwt, " ".join(OKTA_DEFAULT_SCOPE))


@configspec
class OktaAppCredentials(OktaCredentials):
    private_key_path: TSecretStrValue = dlt.secrets.value
    client_id: str = dlt.config.value

    def auth(self) -> str:
        return "app"

    def fetch_token(self) -> Token:
        return _app_token(
            OktaAuth(private_key_path=self.private_key_path),
            self.base_url,
            self.client_id,
        )

    @property
    def header(self) -> str:
        return f"Bearer {self.fetch_token().access_token}"


@configspec
class OktaEncodedAppCredentials(OktaCredentials):
    private_key_b64: TSecretStrValue = dlt.secrets.value
    client_id: str = dlt.config.value

    def auth(self) -> str:
        return "app"

    def fetch_token(self) -> Token:
        decoded_credentials = b64decode(self.private_key_b64).decode("utf-8")
        return _app_token(
            OktaAuth(private_key_string=decoded_credentials),
            self.base_url,
            self.client_id,
        )

    @property
    def header(self) -> str:
        return f"Bearer {self.fetch_token().access_token}"


@configspec
class OktaTokenCredentials(OktaCredentials):
    token: TSecretStrValue = dlt.secrets.value

    def auth(self) -> str:
        return "token"

    @property
    def header(self) -> str:
        return f"SSWS {self.token}"


def _request_auth(
    credentials: Union[
        OktaAppCredentials, OktaEncodedAppCredentials, OktaTokenCredentials
    ],
):
    if isinstance(credentials, (OktaAppCredentials, OktaEncodedAppCredentials)):
        return OktaBearerAuth(credentials.fetch_token)
    return APIKeyAuth(
        name="Authorization", api_key=credentials.header, location="header"
    )
