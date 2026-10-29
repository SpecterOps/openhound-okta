"""Validate local Okta/BHE configuration and storage without network requests."""

import importlib.metadata
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Final, get_args
from urllib.parse import ParseResult, urlparse

import dlt
from dlt.common.configuration import resolve_configuration
from dlt.common.configuration.exceptions import ConfigFieldMissingException
from joserfc.jwk import RSAKey

from openhound_okta.utils.auth import (
    CREDENTIALS_SECTIONS,
    AnyOktaCredentials,
    OktaAppCredentials,
    OktaAuth,
    OktaClientSecretCredentials,
    OktaCredentials,
    OktaEncodedAppCredentials,
    OktaPrivateKeyCredentials,
    OktaTokenCredentials,
)

# Dotted form of the credentials section, as users see it in secrets.toml.
CREDENTIALS_PREFIX: Final[str] = ".".join(CREDENTIALS_SECTIONS)
# Configuration section of openhound's BloodHound Enterprise destination.
BHE_DESTINATION_SECTION: Final[str] = "destination.bloodhoundenterprise"


class PreflightError(ValueError):
    """A configuration error whose message contains no credential values."""


def required(name: str, value: object) -> str:
    """Reject empty and example values without displaying their contents.

    Args:
        name: Configuration key, used in the error message only.
        value: The configured value.

    Returns:
        The value as a string.

    Raises:
        PreflightError: The value is missing, blank, or still an example
            placeholder from the shipped `.example` files.
    """
    if value is None or not str(value).strip() or "REPLACE_WITH" in str(value):
        raise PreflightError(f"Set {name} in the .dlt files or the environment")
    return str(value)


def https_url(name: str, value: str) -> None:
    """Require an HTTPS URL with a hostname and without embedded credentials.

    Paths and query strings are allowed: the BHE tenant URL may carry them.
    The Okta base URL is stricter, but the credentials spec validates it.

    Args:
        name: Configuration key, used in the error message only.
        value: The configured URL.

    Raises:
        PreflightError: The URL is not HTTPS, has no hostname, or contains
            user info.
    """
    parsed: ParseResult = urlparse(value)
    # Plain HTTP would send the BHE token in clear text.
    if parsed.scheme != "https" or not parsed.hostname:
        raise PreflightError(f"Set a valid HTTPS URL for {name}")
    # Embedded credentials (https://user:secret@host) bypass the token fields
    # and could leak into logs.
    if parsed.username or parsed.password:
        raise PreflightError(f"Remove user info from the URL for {name}")


def check_bhe_credentials() -> None:
    """Validate the BloodHound Enterprise tenant URL and collector client token.

    Raises:
        PreflightError: A value is missing or a placeholder, or the URL is not
            a usable HTTPS URL.
    """
    # Upstream declares the tenant URL as ordinary configuration, so it may
    # live in config.toml; dlt.config also searches the secret providers.
    url_name: str = f"{BHE_DESTINATION_SECTION}.url"
    https_url(url_name, required(url_name, dlt.config.get(url_name)))
    # The collector client token is a secret and may only come from secret
    # providers (secrets.toml or the environment); its parts are opaque.
    for field in ("token_id", "token_key"):
        name: str = f"{BHE_DESTINATION_SECTION}.{field}"
        required(name, dlt.secrets.get(name))


def resolve_okta_credentials() -> OktaCredentials:
    """Resolve whichever Okta credential kind is configured.

    The kinds are tried in the order the collector's source tries them, so the
    preflight selects exactly the credentials a collection would use. Resolving
    also validates the base URL through the spec's `on_resolved` hook.

    Returns:
        The resolved credentials of the first kind whose fields are all set.

    Raises:
        PreflightError: No kind is fully configured, or the base URL is not an
            HTTPS origin.
    """
    for spec in get_args(AnyOktaCredentials):
        try:
            return resolve_configuration(spec(), sections=CREDENTIALS_SECTIONS)
        except ConfigFieldMissingException:
            # This kind is not configured; try the next one, like dlt does.
            continue
        except ValueError as exc:
            # Base URL validation failed; its messages contain no credential values.
            raise PreflightError(str(exc)) from exc
    raise PreflightError(
        f"Set {CREDENTIALS_PREFIX}.private_key_path, private_key_b64, client_secret "
        "or token in the .dlt files or the environment"
    )


def check_private_key(credentials: OktaPrivateKeyCredentials) -> None:
    """Require a private RSA JWK with a kid and sign a token with it offline.

    Args:
        credentials: Private key credentials with the key as a file or base64.

    Raises:
        PreflightError: The key setting is a placeholder, the JWK has no kid,
            or it holds only a public key.
        Exception: Unreadable or malformed key material; the caller suppresses
            the details because they may contain the key.
    """
    # Catch example placeholders before trying to read them as a key.
    if isinstance(credentials, OktaAppCredentials):
        required(f"{CREDENTIALS_PREFIX}.private_key_path", credentials.private_key_path)
    elif isinstance(credentials, OktaEncodedAppCredentials):
        required(f"{CREDENTIALS_PREFIX}.private_key_b64", credentials.private_key_b64)
    key_manager: OktaAuth = credentials.key_manager()
    key_data: dict[str, Any] = key_manager.private_key
    # Okta matches the assertion to the registered key by its kid.
    required("the Okta JWK kid", key_data.get("kid"))
    # A public-only JWK parses fine but cannot sign anything.
    if not RSAKey.import_key(key_data).is_private:
        raise PreflightError("The Okta JWK must contain an RSA private key")
    # Exercise the same RS256 signing path used by the collector, offline.
    key_manager.jwt(
        key_data, credentials.client_id, f"{credentials.base_url}/oauth2/v1/token"
    )


def check_okta_credentials() -> str:
    """Validate the configured Okta credentials and name their kind.

    Returns:
        A short label of the credential kind for the success message.

    Raises:
        PreflightError: A required setting is missing or a placeholder, or the
            key material is invalid.
    """
    credentials: OktaCredentials = resolve_okta_credentials()
    # The spec accepts an example host as a valid origin; placeholders are
    # caught here instead.
    required(f"{CREDENTIALS_PREFIX}.base_url", credentials.base_url)
    if isinstance(credentials, OktaPrivateKeyCredentials):
        # Both private key forms sign a client assertion for the client ID.
        required(f"{CREDENTIALS_PREFIX}.client_id", credentials.client_id)
        check_private_key(credentials)
        return "private key"
    if isinstance(credentials, OktaClientSecretCredentials):
        # The secret is only used at the token endpoint; nothing to parse.
        required(f"{CREDENTIALS_PREFIX}.client_id", credentials.client_id)
        required(f"{CREDENTIALS_PREFIX}.client_secret", credentials.client_secret)
        return "client secret"
    if isinstance(credentials, OktaTokenCredentials):
        # An SSWS token is sent as is; there is no client ID.
        required(f"{CREDENTIALS_PREFIX}.token", credentials.token)
        return "API token"
    raise PreflightError("Unsupported Okta credential kind")


def main() -> None:
    """Resolve credentials, validate them offline, and probe persistent storage.

    Raises:
        PreflightError: A configuration value is missing or invalid.
        OSError: A storage directory is missing or not writable.
    """
    check_bhe_credentials()
    kind: str = check_okta_credentials()

    # Every directory the scheduler writes to must exist and be writable by
    # the container user before a collection starts.
    for directory in (
        Path.cwd(),
        Path(os.environ["DLT_DATA_DIR"]),
        Path(os.environ["PIPELINES_DIR"]),
        Path(os.environ["RUNTIME__LOG_PATH"]),
        Path("/tmp/openhound"),
    ):
        with tempfile.TemporaryFile(mode="w+", dir=directory) as probe:
            probe.write("ok")

    version: str = importlib.metadata.version("openhound-okta")
    print(f"PASS: BHE credentials and Okta {kind} credentials resolve and validate.")
    print("PASS: working, DLT, pipeline, log, and raw-output directories are writable.")
    print("Okta collector version:", version)
    print("Preflight does not authenticate to Okta or BHE.")


if __name__ == "__main__":
    try:
        main()
    except PreflightError as exc:
        sys.exit(f"Preflight failed: {exc}")
    except Exception:  # noqa: BLE001 - third-party errors can contain secrets
        # Provider/key parsing errors may include secrets: suppress their details.
        sys.exit(
            "Preflight failed: check configuration, Okta credentials, mounted-file "
            "permissions, storage, and installed collector package. Error details "
            "suppressed."
        )
