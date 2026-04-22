from dlt.extract.source import DltSource
from openhound.core.app import OpenHound
from openhound.core.collect import CollectContext
from openhound.core.convert import ConvertContext
from openhound.core.preproc import PreProcContext

from openhound_okta.transforms import transforms
from openhound_okta.lookup import OktaLookup

app = OpenHound("okta", source_kind="Okta", help="OpenGraph collector for Okta")


@app.collect()
def collect(ctx: CollectContext) -> DltSource:
    """Register a Typer CLI command that collects Okta resources and stores them (filtered) on disk.

    Args:
        ctx (CollectContext): Returns DLT pipeline context.
    """
    from openhound_okta.source import source as okta_source

    return okta_source()


@app.convert(lookup=OktaLookup)
def convert(ctx: ConvertContext) -> tuple[DltSource, dict]:
    """Register a Typer CLI command that converts previously collected Okta resources into OpenGraph nodes and edges.

    Args:
        ctx (ConvertContext): Returns DLT pipeline context.
    """
    from openhound_okta.source import source as okta_source

    return okta_source(), {"tenant": "somethingsomething"}


@app.preproc(transformer=transforms)
def preprocess(ctx: PreProcContext):
    return {
        "organization": "organization",
        "users": "users",
        "groups": "groups",
        "applications": "applications",
        "application_secrets": "application_secrets",
        "devices": "devices",
        "authorization_servers": "authorization_servers",
        "identity_providers": "identity_providers",
        "policies": "policies",
        "resources": "resources",
        "user_role_assignments": "user_role_assignments",
        "group_role_assignments": "group_role_assignments",
        "client_role_assignments": "client_role_assignments",
        "custom_role_permissions": "custom_role_permissions",
    }
