"""Validate local Okta/BHE configuration and storage without network requests."""

import importlib.metadata
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import dlt
from dlt.common.configuration import resolve_configuration
from joserfc.jwk import RSAKey

from openhound_okta.source import OktaAppCredentials


class PreflightError(ValueError):
    """A configuration error whose message contains no credential values."""


def required(name: str, value: object) -> str:
    """Reject empty and example values without displaying their contents."""
    if value is None or not str(value).strip() or "REPLACE_WITH" in str(value):
        raise PreflightError(f"Set {name} in .dlt/secrets.toml or the environment")
    return str(value)


def https_url(name: str, value: str) -> None:
    """Require an HTTPS endpoint without embedded credentials."""
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise PreflightError(f"Set a valid HTTPS URL for {name}")


def main() -> None:
    """Resolve credentials, validate the RSA JWK, and probe persistent storage."""
    for field in ("url", "token_id", "token_key"):
        name = f"destination.bloodhoundenterprise.{field}"
        value = required(name, dlt.secrets.get(name))
        if field == "url":
            https_url(name, value)

    credentials = resolve_configuration(
        OktaAppCredentials(),
        sections=("sources", "source", "okta", "credentials"),
    )
    for field in ("base_url", "client_id", "private_key_path"):
        required(f"sources.source.okta.credentials.{field}", getattr(credentials, field))
    https_url("Okta base_url", credentials.base_url)
    key_data = json.loads(Path(credentials.private_key_path).read_text())
    required("the Okta JWK kid", key_data.get("kid"))
    key = RSAKey.import_key(key_data)
    if not key.is_private:
        raise PreflightError("The Okta JWK must contain an RSA private key")
    # Exercise the same RS256 signing path used by the collector, offline.
    from openhound_okta.utils.auth import OktaAuth

    OktaAuth(private_key_path=credentials.private_key_path).jwt(
        key_data, credentials.client_id, f"{credentials.base_url}/oauth2/v1/token"
    )

    for directory in (
        Path.cwd(),
        Path(os.environ["DLT_DATA_DIR"]),
        Path(os.environ["PIPELINES_DIR"]),
        Path(os.environ["RUNTIME__LOG_PATH"]),
        Path("/tmp/openhound"),
    ):
        with tempfile.TemporaryFile(mode="w+", dir=directory) as probe:
            probe.write("ok")

    version = importlib.metadata.version("openhound-okta")
    print("PASS: BHE and Okta app credentials resolve; RSA private JWK is valid.")
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
            "Preflight failed: check configuration, RSA JWK, mounted-file permissions, "
            "storage, and installed collector package. Error details suppressed."
        )
