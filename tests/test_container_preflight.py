"""Exercise the Compose preflight with offline dummy credentials."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from joserfc.jwk import RSAKey

PREFLIGHT = Path(__file__).resolve().parents[1] / "docker-compose/check_config.py"


class ContainerPreflightTests(unittest.TestCase):
    """Check real DLT resolution, private JWK validation, and safe failures."""

    def setUp(self) -> None:
        """Create isolated configuration and storage for each invocation."""
        self.storage = tempfile.TemporaryDirectory()
        self.addCleanup(self.storage.cleanup)
        self.root = Path(self.storage.name)
        self.key = RSAKey.generate_key(2048, parameters={"kid": "offline-test"})
        self.key_path = self.root / "key.jwk"
        self.key_path.write_text(json.dumps(self.key.as_dict(private=True)))
        self.env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            # Windows cannot initialise sockets (asyncio import) without it.
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "DLT_PROJECT_DIR": str(self.root),
            "DLT_DATA_DIR": str(self.root),
            "PIPELINES_DIR": str(self.root),
            "RUNTIME__LOG_PATH": str(self.root),
            "RUNTIME__DLTHUB_TELEMETRY": "false",
            "DESTINATION__BLOODHOUNDENTERPRISE__URL": "https://bhe.example.invalid",
            "DESTINATION__BLOODHOUNDENTERPRISE__TOKEN_ID": "offline-id",
            "DESTINATION__BLOODHOUNDENTERPRISE__TOKEN_KEY": "secret-must-not-appear",
            "SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL": "https://okta.example.invalid",
            "SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_ID": "offline-client",
            "SOURCES__SOURCE__OKTA__CREDENTIALS__PRIVATE_KEY_PATH": str(self.key_path),
        }
        Path("/tmp/openhound").mkdir(exist_ok=True)

    def run_preflight(self) -> subprocess.CompletedProcess[str]:
        """Run in a fresh process with network requests forbidden."""
        code = (
            "import runpy, sys; from unittest.mock import patch; "
            "guard = patch('requests.sessions.Session.request', "
            "side_effect=AssertionError('network forbidden')); guard.start(); "
            "runpy.run_path(sys.argv[1], run_name='__main__')"
        )
        return subprocess.run(
            [sys.executable, "-c", code, str(PREFLIGHT)],
            cwd=self.root,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def use_credentials(self, **values: str) -> None:
        """Replace the private key file configuration with another credential kind."""
        for name in ("CLIENT_ID", "PRIVATE_KEY_PATH"):
            self.env.pop(f"SOURCES__SOURCE__OKTA__CREDENTIALS__{name}", None)
        for name, value in values.items():
            self.env[f"SOURCES__SOURCE__OKTA__CREDENTIALS__{name}"] = value

    def assert_passes(self, kind: str) -> None:
        """Require success that names the credential kind and leaks no secret."""
        result: subprocess.CompletedProcess[str] = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Okta {kind} credentials", result.stdout)
        self.assertNotIn("secret-must-not-appear", result.stdout + result.stderr)

    def assert_safe_failure(self) -> None:
        """Require failure without exposing credentials or key material."""
        result = self.run_preflight()
        self.assertNotEqual(result.returncode, 0)
        output = result.stdout + result.stderr
        self.assertIn("Preflight failed:", output)
        self.assertNotIn("secret-must-not-appear", output)
        self.assertNotIn(self.key.as_dict(private=True)["d"], output)
        self.assertNotIn("Traceback", output)

    def test_valid_private_jwk_passes_offline(self) -> None:
        """A complete configuration resolves and signs without network access."""
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Okta collector version:", result.stdout)
        self.assertIn("Okta private key credentials", result.stdout)
        self.assertNotIn("secret-must-not-appear", result.stdout + result.stderr)

    def test_base64_private_jwk_passes_offline(self) -> None:
        """The base64-encoded JWK is validated like the mounted key file."""
        self.use_credentials(
            CLIENT_ID="offline-client",
            PRIVATE_KEY_B64=base64.b64encode(self.key_path.read_bytes()).decode(),
        )
        self.assert_passes("private key")

    def test_client_secret_passes_offline(self) -> None:
        """An API Service Integration client secret needs no key material."""
        self.use_credentials(
            CLIENT_ID="offline-client", CLIENT_SECRET="secret-must-not-appear"
        )
        self.assert_passes("client secret")

    def test_api_token_passes_offline(self) -> None:
        """An SSWS API token needs neither a client ID nor key material."""
        self.use_credentials(TOKEN="secret-must-not-appear")
        self.assert_passes("API token")

    def test_client_secret_placeholder_fails(self) -> None:
        """Reject an example client secret like any other placeholder."""
        self.use_credentials(
            CLIENT_ID="offline-client", CLIENT_SECRET="REPLACE_WITH_CLIENT_SECRET"
        )
        self.assert_safe_failure()

    def test_missing_credentials_fail(self) -> None:
        """Reject a configuration with a base URL but no credential kind."""
        self.use_credentials()
        self.assert_safe_failure()

    def test_placeholders_and_insecure_urls_fail(self) -> None:
        """Reject incomplete secrets and plaintext source/destination endpoints."""
        for field, value in (
            ("DESTINATION__BLOODHOUNDENTERPRISE__TOKEN_KEY", "REPLACE_WITH_TOKEN"),
            ("DESTINATION__BLOODHOUNDENTERPRISE__URL", "http://bhe.example.invalid"),
            (
                "SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL",
                "http://okta.example.invalid",
            ),
            ("SOURCES__SOURCE__OKTA__CREDENTIALS__CLIENT_ID", "REPLACE_WITH_CLIENT_ID"),
        ):
            with self.subTest(field=field):
                original = self.env[field]
                self.env[field] = value
                self.assert_safe_failure()
                self.env[field] = original

    def test_okta_base_url_must_be_an_origin(self) -> None:
        """Reject URL suffixes that would corrupt Okta endpoint construction."""
        field = "SOURCES__SOURCE__OKTA__CREDENTIALS__BASE_URL"
        for suffix in (
            "/",
            "/oauth2/default",
            "?tenant=example",
            "#fragment",
            "/;param=x",
        ):
            with self.subTest(suffix=suffix):
                self.env[field] = f"https://okta.example.invalid{suffix}"
                self.assert_safe_failure()

    def test_bhe_url_suffixes_remain_supported(self) -> None:
        """Origin-only validation must not change BHE URL acceptance."""
        self.env["DESTINATION__BLOODHOUNDENTERPRISE__URL"] = (
            "https://bhe.example.invalid/path;param=x?tenant=example#fragment"
        )
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_private_keys_fail_safely(self) -> None:
        """Reject missing files, public-only keys, absent kid, and malformed JSON."""
        private = self.key.as_dict(private=True)
        for data in (
            "secret-must-not-appear",
            json.dumps(self.key.as_dict()),
            json.dumps({k: v for k, v in private.items() if k != "kid"}),
        ):
            with self.subTest(data_type="invalid-key"):
                self.key_path.write_text(data)
                self.assert_safe_failure()
        self.key_path.unlink()
        self.assert_safe_failure()

    def test_unwritable_storage_fails(self) -> None:
        """Reject pipeline paths that cannot hold persistent state."""
        self.env["PIPELINES_DIR"] = str(self.root / "missing-directory")
        self.assert_safe_failure()


if __name__ == "__main__":
    unittest.main()
