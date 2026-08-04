import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests
from joserfc import jwt
from joserfc.jwk import RSAKey

from ..models.token import Token

logger = logging.getLogger(__name__)


class OktaAuth:
    """Okta public/private key manager"""

    def __init__(
            self,
            private_key_path: str | None = None,
            private_key_string: str | None = None,
    ):
        if not private_key_path and not private_key_string:
            raise ValueError("Either private_key_path or private_key_string must be configured")
        self.private_key_path = Path(private_key_path) if private_key_path else None
        self.private_key_string = private_key_string

    def generate_private_key(self) -> None:
        """Generate a new private key and save it to the specified path."""
        if self.private_key_path is None:
            raise ValueError("private_key_path must be configured to generate a key")
        rsa_key = RSAKey.generate_key()
        private_key = rsa_key.as_pem(private=True)
        self.private_key_path.write_bytes(private_key)

    @property
    def private_key(self) -> dict:
        """Load the private key from the specified path."""

        if self.private_key_string:
            logger.info("Loaded private key from configured string")
            return json.loads(self.private_key_string)

        if self.private_key_path is None:
            raise ValueError("private_key_path must be configured")
        logger.info(f"Loaded private key from {self.private_key_path}")
        return json.loads(self.private_key_path.read_text())

    def jwt(
            self, private_key: dict, client_id: str, audience: str, exp_delta: int = 60
    ) -> str:
        """Returns a JWT token for Okta authentication

        Args:
            private_key (str): The private key used as string
            client_id (str): The application client id
            audience (str): The audience
            exp_delta (int, optional): The default expiry in minutes. Defaults to 60.

        Returns:
            str: The JWT token.
        """
        expire = int((datetime.now(UTC) + timedelta(minutes=exp_delta)).timestamp())
        header = {"alg": "RS256"}
        claims = {
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "exp": expire,
        }

        private_key_import = RSAKey.import_key(private_key)
        header["kid"] = private_key["kid"]
        jwt_token = jwt.encode(header=header, claims=claims, key=private_key_import)
        return jwt_token

    def token(self, base_url: str, jwt: str, scope: str) -> str:
        headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "cache-control": "no-cache",
        }

        data = {
            "grant_type": "client_credentials",
            "scope": scope,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt,
        }
        response = requests.post(
            f"{base_url}/oauth2/v1/token", headers=headers, data=data
        )
        response_model = Token.model_validate(response.json())
        return response_model.access_token
