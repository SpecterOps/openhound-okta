"""Regression tests for BED-10001: plaintext ``client_secret`` values returned by
Okta's application secret listing endpoint must not reach collection artifacts.

Runs the real collect -> preproc path (dlt filesystem + DuckDB, not stubs)
and inspects every raw JSONL file and every DuckDB table, including nested
JSON columns, for the synthetic secret.
"""

import gzip
import json
from pathlib import Path
from typing import cast

import dlt
import duckdb

from openhound.core.collect import Collector
from openhound.core.preproc import PreProcessor
from openhound_okta.kinds import edges as ek, nodes as nk
from openhound_okta.lookup import OktaLookup
from openhound_okta.models import ApplicationSecrets
from openhound_okta.source import (
    ClientPool,
    SourceContext,
    application_secrets,
    applications,
    identity_providers,
    organization,
)
from openhound_okta.transforms import transforms

PLAINTEXT_SECRET = "SYNTHETIC-PLAINTEXT-SECRET-bed10001"
SECRET_HASH = "yk4SVx4sUWVJVbHt6M-UPA"

ORG = {
    "id": "00oOrg1",
    "subdomain": "example",
    "status": "ACTIVE",
    "created": "2026-01-01T00:00:00Z",
}

APPLICATION = {
    "id": "app-1",
    "orn": "orn:okta:idp:example:apps:app-1",
    "name": "oidc_client",
    "label": "OIDC App",
    "status": "ACTIVE",
    "created": "2026-01-01T00:00:00Z",
    "signOnMode": "OPENID_CONNECT",
    "credentials": {
        "oauthClient": {
            "client_id": "app-1",
            "token_endpoint_auth_method": "client_secret_basic",
        }
    },
}

# Shape of GET /api/v1/apps/{appId}/credentials/secrets, which always includes
# the plaintext client_secret.
SECRET_ITEM = {
    "id": "secret-1",
    "status": "ACTIVE",
    "client_secret": PLAINTEXT_SECRET,
    "secret_hash": SECRET_HASH,
    "created": "2026-01-01T00:00:00Z",
    "lastUpdated": "2026-01-02T00:00:00Z",
    "_links": {
        "deactivate": {
            "href": "https://example.okta.com/api/v1/apps/app-1/credentials/"
            "secrets/secret-1/lifecycle/deactivate",
            "hints": {"allow": ["POST"]},
        }
    },
}


# Shape of GET /api/v1/idps for an OIDC identity provider, whose protocol
# credentials include the plaintext client_secret.
IDP_PLAINTEXT_SECRET = "SYNTHETIC-IDP-SECRET-bed10001"
IDENTITY_PROVIDER = {
    "id": "idp-1",
    "type": "OIDC",
    "name": "Example OIDC IdP",
    "status": "ACTIVE",
    "created": "2026-01-01T00:00:00Z",
    "lastUpdated": "2026-01-02T00:00:00Z",
    "protocol": {
        "type": "OIDC",
        "endpoints": {
            "authorization": {
                "url": "https://idp.example.com/authorize",
                "binding": "HTTP-REDIRECT",
            }
        },
        "credentials": {
            "client": {
                "client_id": "idp-client-id",
                "client_secret": IDP_PLAINTEXT_SECRET,
            }
        },
    },
}


class StubPool:
    """ClientPool stand-in serving canned pages for the secret collection path."""

    def paginate(self, path: str, **kwargs: object):
        pages = {
            "/api/v1/org": [ORG],
            "/api/v1/apps": [[APPLICATION]],
            "/api/v1/apps/app-1/credentials/secrets": [[SECRET_ITEM]],
            "/api/v1/idps": [[IDENTITY_PROVIDER]],
        }
        return pages[path]


def make_ctx() -> SourceContext:
    return SourceContext(
        pool=cast(ClientPool, StubPool()), tenant_domain="example.okta.com"
    )


def test_collect_and_preproc_artifacts_contain_no_plaintext_client_secret(
    tmp_path: Path,
):
    raw_dir = tmp_path / "raw" / "okta"
    lookup_file = tmp_path / "lookup.duckdb"
    ctx = make_ctx()

    @dlt.source(name="okta", max_table_nesting=0)
    def fake_source():
        applications_resource = applications(ctx)
        yield organization(ctx)
        yield applications_resource
        yield applications_resource | application_secrets(ctx)
        yield identity_providers(ctx)

    Collector(name="okta", output_path=raw_dir).run(fake_source())

    # Raw JSONL collection artifacts.
    jsonl_files = list(raw_dir.rglob("*.jsonl.gz"))
    for path in jsonl_files:
        content = gzip.decompress(path.read_bytes()).decode()
        assert PLAINTEXT_SECRET not in content
        assert IDP_PLAINTEXT_SECRET not in content

    secret_rows = [
        json.loads(line)
        for path in jsonl_files
        if "application_secrets" in str(path)
        for line in gzip.decompress(path.read_bytes()).decode().splitlines()
        if line
    ]
    # DLT serializes the validated model: snake_case keys, normalized timestamps,
    # and the nested _links extra retained. Only client_secret is gone.
    assert [
        {k: v for k, v in row.items() if not k.startswith("_dlt_")}
        for row in secret_rows
    ] == [
        {
            "app_id": "app-1",
            "app_name": "oidc_client",
            "id": "secret-1",
            "status": "ACTIVE",
            "secret_hash": SECRET_HASH,
            "created": "2026-01-01T00:00:00+00:00",
            "last_updated": "2026-01-02T00:00:00+00:00",
            "_links": SECRET_ITEM["_links"],
        }
    ]

    PreProcessor(
        name="okta",
        input_path=raw_dir / "okta",
        output_file=lookup_file,
        transformer=transforms,
    ).run(
        resources={
            "organization": "organization",
            "applications": "applications",
            "application_secrets": "application_secrets",
            "identity_providers": "identity_providers",
        }
    )

    con = duckdb.connect(str(lookup_file), read_only=True)
    try:
        tables = [
            name
            for (name,) in con.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'okta'"
            ).fetchall()
        ]
        assert "application_secrets" in tables

        # Every table, every column (nested JSON columns included), every row.
        for table in tables:
            columns = [
                name
                for (name,) in con.execute(
                    "SELECT column_name FROM information_schema.columns "
                    f"WHERE table_schema = 'okta' AND table_name = '{table}'"
                ).fetchall()
            ]
            assert "client_secret" not in columns, table
            for row in con.execute(f'SELECT * FROM okta."{table}"').fetchall():
                assert PLAINTEXT_SECRET not in repr(row), table
                assert IDP_PLAINTEXT_SECRET not in repr(row), table

        # The IdP keeps its client_id; only the nested client_secret is gone.
        (protocol,) = con.execute(
            "SELECT protocol FROM okta.identity_providers"
        ).fetchone()
        assert json.loads(protocol)["credentials"]["client"] == {
            "client_id": "idp-client-id"
        }

        # Metadata needed to model the secret survives the full path.
        (secret_id, secret_hash, status, created, last_updated, links) = con.execute(
            "SELECT id, secret_hash, status, created, last_updated, _links "
            "FROM okta.application_secrets"
        ).fetchone()
        assert (secret_id, secret_hash, status) == ("secret-1", SECRET_HASH, "ACTIVE")
        assert created is not None and last_updated is not None
        assert "deactivate" in json.loads(links)

        lookup = OktaLookup(con)
        assert lookup.application_secret_ids("app-1") == (("secret-1",),)

        # Convert rehydrates the model from the collected row.
        secret = ApplicationSecrets.model_validate(secret_rows[0])
        secret._lookup = lookup
        secret._extras = {"tenant": "example.okta.com"}

        node = secret.as_node
        assert nk.CLIENT_SECRET in node.kinds
        assert node.properties.name == SECRET_HASH.upper()
        assert node.properties.status == "ACTIVE"

        (edge,) = list(secret.edges)
        assert edge.kind == ek.SECRET_OF
        assert edge.start.value == "SECRET-1"
        assert edge.end.value == "APP-1"
    finally:
        con.close()
