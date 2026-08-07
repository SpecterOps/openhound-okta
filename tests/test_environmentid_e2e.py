"""End-to-end regression test for `environmentid` propagation.

Runs the real collect -> preproc -> convert pipeline (using dlt/DuckDB, not
stubs) to confirm `environmentid` comes out uppercase, matching the
uppercased Organization node `id`. This guards against `environmentid`
being read from a pre-fix (lowercase) cached value anywhere in preproc,
since it is sourced via `OktaLookup.org_id()` which reads directly from the
DuckDB lookup table populated during preproc, bypassing the `OktaNode`
property-assignment path where `id`/`name` uppercasing happens.
"""

import tempfile
from pathlib import Path

import dlt
import duckdb

from openhound.core.collect import Collector
from openhound.core.preproc import PreProcessor
from openhound_okta.lookup import OktaLookup
from openhound_okta.models import User
from openhound_okta.transforms import transforms

ORG_ID = "00oOrgMixedCase1"
USER_ID = "00uUserMixedCase1"


@dlt.resource(name="organization")
def _organization_resource():
    yield {
        "id": ORG_ID,
        "subdomain": "example",
        "status": "ACTIVE",
        "created": "2026-01-01T00:00:00Z",
    }


@dlt.resource(name="users")
def _users_resource():
    yield {
        "id": USER_ID,
        "created": "2026-01-01T00:00:00Z",
        "status": "ACTIVE",
        "profile": {
            "login": "alice@example.com",
            "displayName": "Alice",
            "email": "a@example.com",
            "firstName": "A",
            "lastName": "E",
        },
    }


@dlt.source(name="okta")
def _fake_source():
    yield _organization_resource()
    yield _users_resource()


def test_environmentid_is_uppercase_after_full_collect_preproc_convert_pipeline():
    tmp = Path(tempfile.mkdtemp())
    raw_dir = tmp / "raw" / "okta"
    lookup_file = tmp / "lookup.duckdb"

    collector = Collector(name="okta", output_path=raw_dir)
    collector.run(_fake_source())

    preprocessor = PreProcessor(
        name="okta",
        input_path=raw_dir / "okta",
        output_file=lookup_file,
        transformer=transforms,
    )
    preprocessor.run(resources={"organization": "organization", "users": "users"})

    con = duckdb.connect(str(lookup_file), read_only=True)
    lookup = OktaLookup(con)

    user = User.model_validate(
        {
            "id": USER_ID,
            "created": "2026-01-01T00:00:00Z",
            "status": "ACTIVE",
            "profile": {
                "login": "alice@example.com",
                "displayName": "Alice",
                "email": "a@example.com",
                "firstName": "A",
                "lastName": "E",
            },
        }
    )
    user._lookup = lookup
    user._extras = {"tenant": "example.okta.com"}

    node = user.as_node

    assert node.id == USER_ID.upper()
    assert node.properties.environmentid == ORG_ID.upper()
    assert node.properties.tenant == ORG_ID

    con.close()
