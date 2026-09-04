from datetime import datetime, timezone
from types import SimpleNamespace

import dlt
import duckdb
import pytest
from dlt.extract.exceptions import ResourceExtractionError
from dlt.pipeline.exceptions import PipelineStepFailed

from openhound_okta.main import preprocessing_resources
from openhound_okta.lookup import OktaLookup
from openhound_okta.models.group_assigned_apps import GroupAssignedApp
from openhound_okta.source import (
    APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE,
    OktaTokenCredentials,
    application_group_assignment_rows,
    applications,
    group_assigned_apps,
    source,
)
from openhound_okta.saml_eligibility import (
    SamlEligibilityPreflight,
    derive_saml_group_eligibility_identity,
)


class RecordingPool:
    def __init__(self, pages):
        self.pages = pages
        self.path = None
        self.kwargs = None

    def paginate(self, path, **kwargs):
        self.path = path
        self.kwargs = kwargs
        yield from self.pages


def application(**overrides):
    values = {
        "id": "0oa-app",
        "name": "example_saml",
        "label": "Example SAML",
        "status": "ACTIVE",
        "last_updated": datetime(2026, 8, 20, tzinfo=timezone.utc),
        "sign_on_mode": "SAML_2_0",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def assignment(group_id="00g-group", **overrides):
    values = {
        "id": group_id,
        "lastUpdated": "2026-08-19T12:34:56.000Z",
        "priority": 0,
        "profile": {
            "role": "administrator",
            "securityAnswer": "must-not-reach-the-graph",
        },
    }
    values.update(overrides)
    return values


def test_application_group_assignments_preserve_parent_and_assignment_evidence():
    pool = RecordingPool([[assignment()]])
    ctx = SimpleNamespace(
        pool=pool,
        application_group_assignments_page_size=APPLICATION_GROUP_ASSIGNMENTS_PAGE_SIZE,
    )

    rows = list(application_group_assignment_rows(application(), ctx))

    assert rows == [
        {
            "id": "0oa-app",
            "group_id": "00g-group",
            "name": "example_saml",
            "label": "Example SAML",
            "status": "ACTIVE",
            "lastUpdated": datetime(2026, 8, 20, tzinfo=timezone.utc),
            "app_sign_on_mode": "SAML_2_0",
            "assignment_last_updated": "2026-08-19T12:34:56.000Z",
            "assignment_priority": 0,
            "assignment_profile": {
                "role": "administrator",
                "securityAnswer": "must-not-reach-the-graph",
            },
        }
    ]
    assert pool.path == "/api/v1/apps/0oa-app/groups"
    assert pool.kwargs == {"params": {"limit": 200}}


def test_application_group_assignments_consume_every_page_and_deduplicate_identical_rows(
    caplog,
):
    duplicate = assignment()
    pool = RecordingPool(
        [
            [duplicate, assignment("00g-second", priority=None)],
            [duplicate, duplicate, assignment("00g-third", priority=3)],
        ]
    )
    ctx = SimpleNamespace(
        pool=pool,
        application_group_assignments_page_size=200,
    )

    rows = list(application_group_assignment_rows(application(), ctx))

    assert [row["group_id"] for row in rows] == [
        "00g-group",
        "00g-second",
        "00g-third",
    ]
    assert rows[1]["assignment_priority"] is None
    duplicate_diagnostics = [
        record
        for record in caplog.records
        if "deduplicated" in record.message
        and "application-group assignment" in record.message
    ]
    assert len(duplicate_diagnostics) == 1
    assert "deduplicated 2 identical application-group assignment" in caplog.text
    assert "administrator" not in caplog.text
    assert "must-not-reach-the-graph" not in caplog.text


@pytest.mark.parametrize(
    "malformed_assignment",
    [
        None,
        {},
        assignment(group_id=None),
        assignment(group_id=""),
        assignment(group_id=" "),
    ],
)
def test_application_group_assignments_fail_on_missing_group_id(
    malformed_assignment,
):
    pool = RecordingPool([[malformed_assignment]])
    ctx = SimpleNamespace(
        pool=pool,
        application_group_assignments_page_size=200,
    )

    with pytest.raises(ValueError, match="without a usable group ID"):
        list(application_group_assignment_rows(application(), ctx))


def test_application_group_assignments_accept_complete_empty_response():
    pool = RecordingPool([[]])
    ctx = SimpleNamespace(
        pool=pool,
        application_group_assignments_page_size=200,
    )

    rows = list(
        application_group_assignment_rows(
            application(status="INACTIVE"),
            ctx,
        )
    )

    assert rows == []
    assert pool.path == "/api/v1/apps/0oa-app/groups"


def test_application_group_assignments_fail_on_conflicting_duplicate():
    pool = RecordingPool([[assignment(priority=0), assignment(priority=1)]])
    ctx = SimpleNamespace(
        pool=pool,
        application_group_assignments_page_size=200,
    )

    with pytest.raises(ValueError, match="conflicting application-group assignments"):
        list(application_group_assignment_rows(application(), ctx))


def test_application_group_assignments_stream_first_row_before_later_page_failure():
    class FailingPool(RecordingPool):
        def paginate(self, path, **kwargs):
            self.path = path
            self.kwargs = kwargs
            yield [assignment()]
            raise RuntimeError("opaque continuation failed")

    ctx = SimpleNamespace(
        pool=FailingPool([]),
        application_group_assignments_page_size=200,
    )
    rows = application_group_assignment_rows(application(), ctx)

    assert next(rows)["group_id"] == "00g-group"
    with pytest.raises(RuntimeError, match="opaque continuation failed"):
        next(rows)


def test_application_group_assignments_ignore_mapping_key_order_in_duplicates():
    pool = RecordingPool(
        [
            [
                assignment(
                    profile={"role": "administrator", "nested": {"a": 1, "b": 2}}
                ),
                assignment(
                    profile={"nested": {"b": 2, "a": 1}, "role": "administrator"}
                ),
            ]
        ]
    )
    ctx = SimpleNamespace(pool=pool, application_group_assignments_page_size=200)

    rows = list(application_group_assignment_rows(application(), ctx))

    assert [row["group_id"] for row in rows] == ["00g-group"]


@pytest.mark.parametrize(
    "conflicting_assignment",
    [
        assignment(priority=None),
        assignment(lastUpdated="2026-08-19T12:34:57.000Z"),
        assignment(profile={"role": "user"}),
    ],
)
def test_application_group_assignments_fail_on_different_duplicate_evidence(
    conflicting_assignment,
    caplog,
):
    pool = RecordingPool([[assignment(), conflicting_assignment]])
    ctx = SimpleNamespace(pool=pool, application_group_assignments_page_size=200)

    rows = application_group_assignment_rows(application(), ctx)

    assert next(rows)["assignment_priority"] == 0
    with pytest.raises(ValueError, match="conflicting application-group assignments"):
        next(rows)
    assert "administrator" not in caplog.text
    assert "must-not-reach-the-graph" not in caplog.text


def test_application_group_assignment_pipeline_propagates_page_failure(caplog):
    class FailingPool(RecordingPool):
        def paginate(self, path, **kwargs):
            self.path = path
            self.kwargs = kwargs
            yield [assignment()]
            raise RuntimeError("opaque continuation failed")

    ctx = SimpleNamespace(
        pool=FailingPool([]),
        application_group_assignments_page_size=200,
    )
    parent = dlt.resource([application()], name="failing_applications")
    pipeline_resource = parent | group_assigned_apps(ctx)

    with pytest.raises(
        ResourceExtractionError, match="opaque continuation failed"
    ) as exc_info:
        list(pipeline_resource)

    assert isinstance(exc_info.value.__cause__, RuntimeError)

    record = next(
        record
        for record in caplog.records
        if "authoritative application-group assignment collection failed"
        in record.message
    )
    assert record.resource == "group_assigned_apps"
    assert record.phase == "resource_iteration"


def test_application_inventory_pipeline_propagates_continuation_failure():
    class FailingApplicationsPool:
        def paginate(self, path, **kwargs):
            if path == "/api/v1/apps":
                assert kwargs == {}
                yield [
                    {
                        "id": "0oa-app",
                        "orn": "orn:okta:idp:00o-org:apps:bookmark:0oa-app",
                        "name": "bookmark",
                        "label": "Bookmark",
                        "status": "ACTIVE",
                        "created": "2026-08-20T00:00:00Z",
                        "signOnMode": "BOOKMARK",
                    }
                ]
                raise RuntimeError("application inventory continuation failed")

            assert path == "/api/v1/apps/0oa-app/groups"
            assert kwargs == {"params": {"limit": 200}}
            yield []

    ctx = SimpleNamespace(
        pool=FailingApplicationsPool(),
        application_group_assignments_page_size=200,
    )
    pipeline_resource = applications(ctx) | group_assigned_apps(ctx)

    with pytest.raises(
        ResourceExtractionError, match="application inventory continuation failed"
    ) as exc_info:
        list(pipeline_resource)

    assert isinstance(exc_info.value.__cause__, RuntimeError)


@pytest.mark.parametrize("page_size", [20, 200])
def test_application_group_assignment_page_size_accepts_documented_bounds(page_size):
    configured = source(
        credentials=OktaTokenCredentials(
            base_url="https://example.okta.test",
            token="test-token",
        ),
        application_group_assignments_page_size=page_size,
    )

    assert configured.resources["group_assigned_apps"].write_disposition == "replace"


@pytest.mark.parametrize("page_size", [19, 201])
def test_application_group_assignment_page_size_rejects_out_of_range_values(page_size):
    with pytest.raises(
        ValueError,
        match="application_group_assignments_page_size must be between 20 and 200",
    ):
        source(
            credentials=OktaTokenCredentials(
                base_url="https://example.okta.test",
                token="test-token",
            ),
            application_group_assignments_page_size=page_size,
        )


def test_group_assignment_resource_is_seeded_by_shared_applications_resource():
    configured = source(
        credentials=OktaTokenCredentials(
            base_url="https://example.okta.test",
            token="test-token",
        )
    )

    assignment_pipe = configured.resources["group_assigned_apps"]._pipe
    assert assignment_pipe.parent is configured.resources["applications"]._pipe
    assert assignment_pipe.parent.name == "applications"


class GroupLookup:
    def __init__(self, group_ids=("00g-group",)):
        self.group_ids = set(group_ids)

    def group_by_id(self, group_id):
        return group_id in self.group_ids


def test_group_assignment_edge_contains_only_safe_assignment_provenance():
    model = GroupAssignedApp(
        id="0oa-app",
        group_id="00g-group",
        name="example_saml",
        label="Example SAML",
        status="ACTIVE",
        lastUpdated="2026-08-20T00:00:00Z",
        app_sign_on_mode="SAML_2_0",
        assignment_last_updated="2026-08-19T12:34:56Z",
        assignment_priority=0,
        assignment_profile={
            "role": "administrator",
            "securityAnswer": "must-not-reach-the-graph",
        },
    )
    model._lookup = GroupLookup()

    edge = next(model.edges)

    assert edge.start.value == "00G-GROUP"
    assert edge.end.value == "0OA-APP"
    assert edge.properties.traversable is False
    assert edge.properties.assignment_last_updated == datetime(
        2026, 8, 19, 12, 34, 56, tzinfo=timezone.utc
    )
    assert edge.properties.assignment_priority == 0
    assert edge.properties.assignment_profile_fields == ["role", "securityAnswer"]
    assert "administrator" not in repr(edge.properties)
    assert "must-not-reach-the-graph" not in repr(edge.properties)


def test_shadow_mode_emits_non_traversable_group_eligibility_operand():
    class ShadowLookup(GroupLookup):
        def saml_group_assignment_group_ids(self, app_id):
            assert app_id == "0oa-app"
            return ("00g-second", "00g-group")

        def org_id(self):
            return "00o-org"

    model = GroupAssignedApp(
        id="0oa-app",
        group_id="00g-group",
        name="example_saml",
        label="Example SAML",
        status="ACTIVE",
        app_sign_on_mode="SAML_2_0",
    )
    model._lookup = ShadowLookup(group_ids=("00g-group", "00g-second"))
    model._extras = {
        "tenant": "Preview1.Example.Invalid",
        "saml_group_eligibility_mode": "shadow",
    }

    native_assignment, eligibility = list(model.edges)

    assert native_assignment.kind == "Okta_AppAssignment"
    assert eligibility.kind == "SAML_EligibleFor"
    assert eligibility.start.value == "00G-GROUP"
    assert eligibility.end.value == "OKTA:SAML:PROVIDER:0OA-APP"
    assert eligibility.properties.traversable is False
    assert eligibility.properties.schema_contract_version == "opengraph-saml-v0.4.0"
    assert eligibility.properties.eligibility_subject_type == "principal_set"
    assert (
        eligibility.properties.eligibility_expansion_profile
        == "openhound_okta_group_membership_v1"
    )
    assert eligibility.properties.eligibility_source_id == "source://openhound-okta/00O-ORG"
    assert eligibility.properties.eligibility_authority_id == "https://preview1.example.invalid"
    assert (
        eligibility.properties.canonical_policy_identity
        == "any_of:positive_set:00G-GROUP,positive_set:00G-SECOND"
    )
    assert eligibility.properties.policy_evaluability == "static_incomplete"
    assert eligibility.properties.branch_positive_operand_count == 2
    assert {
        eligibility.properties.membership_coverage,
        eligibility.properties.principal_reachability_coverage,
        eligibility.properties.principal_exclusion_coverage,
        eligibility.properties.policy_evaluation_coverage,
        eligibility.properties.claim_evidence_coverage,
    } == {"unproven"}


def test_shadow_mode_consumes_only_contract_coverage_from_a_preflight_ledger():
    class PreflightLookup(GroupLookup):
        def saml_group_assignment_group_ids(self, app_id):
            assert app_id == "0oa-app"
            return ("00g-group",)

        def org_id(self):
            return "00o-org"

        def saml_eligibility_preflight(self, app_id):
            assert app_id == "0oa-app"
            return SamlEligibilityPreflight(
                membership_coverage="complete",
                principal_reachability_coverage="complete",
                principal_exclusion_coverage="complete",
                policy_evaluation_coverage="complete",
                claim_evidence_coverage="incomplete",
            )

    model = GroupAssignedApp(
        id="0oa-app",
        group_id="00g-group",
        name="example_saml",
        label="Example SAML",
        status="ACTIVE",
        app_sign_on_mode="SAML_2_0",
    )
    model._lookup = PreflightLookup(group_ids=("00g-group",))
    model._extras = {
        "tenant": "preview1.example.invalid",
        "saml_group_eligibility_mode": "shadow",
    }

    eligibility = list(model.edges)[1]

    assert eligibility.properties.policy_evaluability == "static_complete"
    assert eligibility.properties.membership_coverage == "complete"
    assert eligibility.properties.principal_reachability_coverage == "complete"
    assert eligibility.properties.principal_exclusion_coverage == "complete"
    assert eligibility.properties.policy_evaluation_coverage == "complete"
    assert eligibility.properties.claim_evidence_coverage == "incomplete"


def test_group_eligibility_identity_matches_the_published_contract_vector():
    identity = derive_saml_group_eligibility_identity(
        source_id="source://openhound-okta/preview1",
        authority_id="https://preview1.example.invalid",
        federation_provider_id="provider-okta-preview1-app-123",
        assigned_group_ids=("group-002", "group-001"),
        group_id="group-001",
    )

    assert identity.canonical_policy_identity == (
        "any_of:positive_set:group-001,positive_set:group-002"
    )
    assert identity.policy_key == "53904144-338b-5f56-8d2a-110b4d3d2922"
    assert identity.partition_key == "d2a8d18c-886d-5e4c-9c72-7a31b51c7021"
    assert identity.branch_key == "53637f13-b4a0-57f3-a1c9-394f958c5c16"
    assert identity.evidence_key == "707fd721-52b2-5697-a428-8075851fcf67"


def test_group_eligibility_uses_single_selector_for_one_group_assignment():
    identity = derive_saml_group_eligibility_identity(
        source_id="source://openhound-okta/org-1",
        authority_id="https://example.okta.test",
        federation_provider_id="OKTA:SAML:PROVIDER:0OA-APP",
        assigned_group_ids=("00G-GROUP",),
        group_id="00G-GROUP",
    )

    assert identity.canonical_policy_identity == "single:positive_set:00G-GROUP"
    assert identity.selector_operator == "single"
    assert identity.branch_positive_operand_count == 1


def test_group_assignment_lookup_is_sorted_distinct_and_cached():
    con = duckdb.connect()
    con.execute("CREATE SCHEMA okta")
    con.execute("CREATE TABLE okta.group_assigned_apps (id VARCHAR, group_id VARCHAR)")
    con.execute(
        "INSERT INTO okta.group_assigned_apps VALUES "
        "('0oa-app', '00g-second'), ('0oa-app', '00g-group'), "
        "('0oa-app', '00g-group'), ('0oa-other', '00g-other')"
    )
    lookup = OktaLookup(con)

    assert lookup.saml_group_assignment_group_ids("0oa-app") == (
        "00g-group",
        "00g-second",
    )
    assert lookup.saml_group_assignment_group_ids("0oa-app") == (
        "00g-group",
        "00g-second",
    )
    assert lookup.saml_group_assignment_group_ids.cache_info().hits == 1


def test_group_assignment_edge_fails_conversion_for_uncollected_group():
    model = GroupAssignedApp(
        id="0oa-app",
        group_id="00g-missing",
        name="example_saml",
        label="Example SAML",
        status="ACTIVE",
    )
    model._lookup = GroupLookup()

    with pytest.raises(ValueError, match="references uncollected Okta group"):
        list(model.edges)


def test_prechange_group_assignment_raw_row_remains_convertible():
    model = GroupAssignedApp(
        id="0oa-app",
        group_id="00g-group",
        name="example_saml",
        label="Example SAML",
        status="ACTIVE",
        lastUpdated="2026-08-20T00:00:00Z",
    )
    model._lookup = GroupLookup()

    edge = next(model.edges)

    assert edge.start.value == "00G-GROUP"
    assert edge.end.value == "0OA-APP"
    assert edge.properties.assignment_last_updated is None
    assert edge.properties.assignment_priority is None
    assert edge.properties.assignment_profile_fields == []


def test_group_assignment_table_is_registered_for_preprocessing():
    resources = preprocessing_resources()

    assert resources["group_assigned_apps"] == "group_assigned_apps"
    assert group_assigned_apps.write_disposition == "replace"


def test_group_assignment_table_replaces_stale_rows(tmp_path):
    pipeline = dlt.pipeline(
        pipeline_name="group_assignment_replace_test",
        pipelines_dir=str(tmp_path / "pipelines"),
        destination=dlt.destinations.duckdb(
            credentials=str(tmp_path / "assignments.duckdb")
        ),
        dataset_name="okta",
    )

    def run_snapshot(group_ids):
        parent = dlt.resource([application()], name="replacement_applications")
        ctx = SimpleNamespace(
            pool=RecordingPool([[assignment(group_id) for group_id in group_ids]]),
            application_group_assignments_page_size=200,
        )
        pipeline.run(parent | group_assigned_apps(ctx))

    def stored_group_ids():
        with pipeline.sql_client() as client:
            return client.execute_sql(
                "SELECT group_id FROM group_assigned_apps ORDER BY group_id"
            )

    run_snapshot(["00g-stale", "00g-current"])
    run_snapshot(["00g-current"])
    assert stored_group_ids() == [("00g-current",)]

    run_snapshot([])
    assert stored_group_ids() == []


def test_group_assignment_failed_continuation_preserves_prior_replacement_snapshot(tmp_path):
    pipeline = dlt.pipeline(
        pipeline_name="group_assignment_atomic_replace_test",
        pipelines_dir=str(tmp_path / "pipelines"),
        destination=dlt.destinations.duckdb(
            credentials=str(tmp_path / "assignments.duckdb")
        ),
        dataset_name="okta",
    )

    def run_snapshot(pool):
        parent = dlt.resource([application()], name="atomic_applications")
        ctx = SimpleNamespace(
            pool=pool,
            application_group_assignments_page_size=200,
        )
        return pipeline.run(parent | group_assigned_apps(ctx))

    def stored_group_ids():
        with pipeline.sql_client() as client:
            return client.execute_sql(
                "SELECT group_id FROM group_assigned_apps ORDER BY group_id"
            )

    run_snapshot(RecordingPool([[assignment("00g-prior")]]))

    class FailingPool(RecordingPool):
        def paginate(self, path, **kwargs):
            yield [assignment("00g-new")]
            raise RuntimeError("opaque continuation failed")

    with pytest.raises(PipelineStepFailed, match="opaque continuation failed"):
        run_snapshot(FailingPool([]))

    assert stored_group_ids() == [("00g-prior",)]
