"""Okta credential specifications and credential-specific authentication adapters."""

from base64 import b64decode
from typing import Final, Union

import dlt
from dlt.common.configuration import configspec
from dlt.common.configuration.specs import CredentialsConfiguration
from dlt.common.typing import TSecretStrValue
from dlt.sources.helpers.rest_client.auth import APIKeyAuth
from requests.auth import AuthBase, HTTPBasicAuth

from .utils.auth import (
    ClientCredentialsGrant,
    OktaAuth,
    OktaBearerAuth,
    Token,
    _base_url_hostname,
    _request_token,
)

# Configuration section under which dlt resolves the source's `credentials`
# argument: `sources.<module>.<source name>.<argument name>`. Code that resolves
# credentials outside the source, such as the container preflight, must use the
# same section to see the same configuration.
CREDENTIALS_SECTIONS: Final[tuple[str, ...]] = (
    "sources",
    "source",
    "okta",
    "credentials",
)
# Okta API scopes requested for every OAuth 2.0 access token; the collector's
# service app or API Service Integration must have exactly these granted.
OKTA_DEFAULT_SCOPE: Final[list[str]] = [
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
    """Base of every Okta credential kind: the org base URL and what it is for.

    Concrete kinds decide how collection requests are authenticated by
    overriding `request_auth`.

    Attributes:
        base_url: Okta org base URL; must be an HTTPS origin.
    """

    base_url: str = dlt.config.value

    def on_resolved(self) -> None:
        """Reject an unusable base URL as soon as dlt resolves the credentials.

        Raises:
            ValueError: `base_url` is not an HTTPS origin.
        """
        _base_url_hostname(self.base_url)

    @property
    def tenant_domain(self) -> str:
        """Case-folded hostname of the Okta org, which scopes graph node IDs.

        Raises:
            ValueError: `base_url` is not an HTTPS origin.
        """
        return _base_url_hostname(self.base_url).casefold()

    def request_auth(self) -> AuthBase:
        """Build the requests auth handler for collection requests.

        Returns:
            The handler that authenticates each request.
        """
        raise NotImplementedError


@configspec
class OktaOAuthCredentials(OktaCredentials):
    """OAuth 2.0 client credentials grant for the collector's default scopes.

    Subclasses define how the client authenticates to the token endpoint:
    with a signed client assertion in the grant body, with a requests auth
    handler, or both. Collection requests then carry the bearer token,
    refreshed by OktaBearerAuth.

    Attributes:
        client_id: OAuth 2.0 client ID.
    """

    client_id: str = dlt.config.value

    def request_auth(self) -> AuthBase:
        """Build the shared, self-refreshing bearer auth for collection requests.

        Returns:
            An OktaBearerAuth that fetches tokens through `fetch_token`.
        """
        return OktaBearerAuth(self.fetch_token)

    def fetch_token(self) -> Token:
        """Request a fresh access token for the default scopes.

        Returns:
            The token response.

        Raises:
            ValueError: `base_url` is not a valid HTTPS URL.
            requests.RequestException: The token request failed after retries,
                or Okta rejected it.
            pydantic.ValidationError: Okta returned an invalid token payload.
        """
        return _request_token(
            self.base_url,
            ClientCredentialsGrant(
                scopes=OKTA_DEFAULT_SCOPE,
                client_assertion=self._client_assertion(),
            ),
            auth=self._grant_auth(),
        )

    def _client_assertion(self) -> str | None:
        """Signed JWT that authenticates the client in the grant body.

        Returns:
            None by default: the client does not authenticate in the body.
        """
        return None

    def _grant_auth(self) -> AuthBase | None:
        """Requests auth handler that authenticates the client through headers.

        Returns:
            None by default.
        """
        return None


@configspec
class OktaPrivateKeyCredentials(OktaOAuthCredentials):
    """Service app using the private_key_jwt method.

    The client assertion is a JWT signed with the app's private key (JWK);
    subclasses decide where the key comes from.
    """

    def key_manager(self) -> OktaAuth:
        """Return the holder of the private key.

        Returns:
            An OktaAuth configured with this credential's key source.
        """
        raise NotImplementedError

    def _client_assertion(self) -> str:
        """Sign a client assertion for the token endpoint.

        Returns:
            The JWT, issued by and for the client ID, addressed to the token
            endpoint.

        Raises:
            KeyError: The private key JWK has no `kid`.
            ValueError: The private key is not JSON.
        """
        key_manager = self.key_manager()
        return key_manager.jwt(
            private_key=key_manager.private_key,
            client_id=self.client_id,
            audience=f"{self.base_url}/oauth2/v1/token",
            exp_delta=60,
        )


@configspec
class OktaAppCredentials(OktaPrivateKeyCredentials):
    """Service app credentials with the private key read from a file.

    Attributes:
        private_key_path: Path to the JWK JSON file.
    """

    private_key_path: TSecretStrValue = dlt.secrets.value

    def key_manager(self) -> OktaAuth:
        """Return a key holder that reads the JWK from `private_key_path`.

        Returns:
            An OktaAuth bound to the key file.
        """
        return OktaAuth(private_key_path=self.private_key_path)


@configspec
class OktaEncodedAppCredentials(OktaPrivateKeyCredentials):
    """Service app credentials with the private key supplied base64-encoded.

    Attributes:
        private_key_b64: Base64-encoded JWK JSON.
    """

    private_key_b64: TSecretStrValue = dlt.secrets.value

    def key_manager(self) -> OktaAuth:
        """Return a key holder for the decoded JWK.

        Returns:
            An OktaAuth bound to the decoded key string.

        Raises:
            binascii.Error: `private_key_b64` is not valid base64.
        """
        return OktaAuth(
            private_key_string=b64decode(self.private_key_b64).decode("utf-8")
        )


@configspec
class OktaClientSecretCredentials(OktaOAuthCredentials):
    """Client secret of an installed Okta API Service Integration.

    Only Okta Integration Network (OIN) API Service Integrations may obtain
    Okta API scopes with the client_secret_basic method. HTTPBasicAuth adds
    the secret to the Authorization header only while the token request is
    prepared, so it never enters the form body, the URL, logs, or validation
    errors.

    Attributes:
        client_secret: Client secret issued when the integration was installed.
    """

    client_secret: TSecretStrValue = dlt.secrets.value

    def _grant_auth(self) -> AuthBase:
        """Return HTTP Basic auth carrying the client ID and secret.

        Returns:
            The requests auth handler for the token request.
        """
        return HTTPBasicAuth(self.client_id, self.client_secret)


@configspec
class OktaTokenCredentials(OktaCredentials):
    """Static SSWS API token, acting as the administrator it was issued to.

    Attributes:
        token: The API token.
    """

    token: TSecretStrValue = dlt.secrets.value

    def request_auth(self) -> AuthBase:
        """Build a static header auth carrying the SSWS token.

        Returns:
            An APIKeyAuth setting the Authorization header on every request.
        """
        return APIKeyAuth(
            name="Authorization", api_key=f"SSWS {self.token}", location="header"
        )


# Every credential kind the source accepts; dlt resolves the first member whose
# fields are all present in the configured secrets.
AnyOktaCredentials = Union[
    OktaAppCredentials,
    OktaEncodedAppCredentials,
    OktaClientSecretCredentials,
    OktaTokenCredentials,
]
