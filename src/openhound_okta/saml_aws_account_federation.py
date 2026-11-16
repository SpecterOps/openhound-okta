"""AWS role values of the Okta "AWS Account Federation" application (`amazon_aws`).

The application gives the SAML `Role` attribute from three sources: roles on a
user or group assignment, group mapping (Group Filter and Role Value Pattern),
and "Join all roles" over both. The source for each rule is the contract guide,
section 11, "Okta: the settings of the AWS Account Federation application"
(`docs/openhound-saml-contract-guide.md` in saml-og-research). That record lists
seven items that Okta does not document. A value that depends on one of them is
written with `incomplete=true` and an `IncompleteReason`, never as a guess. The
README section "SAML Role values of the AWS Account Federation application"
documents each reason.

Issue: SpecterOps/saml-og-research#88, part A.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import regex

from openhound_okta.saml_group_expression import MembershipCheck

ROLE_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/Role"
ROLE_SESSION_NAME_ATTRIBUTE = "https://aws.amazon.com/SAML/Attributes/RoleSessionName"
# `mapping_origin` of the claim mappings that the producer adds for the
# application. Okta shows no attribute statement for them.
ROLE_ORIGIN = "aws_account_federation_role"
ROLE_SESSION_NAME_ORIGIN = "aws_account_federation_role_session_name"


class IncompleteReason(StrEnum):
    """Why a value is incomplete. Declaration order is the order of precedence.

    A value has one `incomplete_reason`; the first member that applies wins.
    """

    ROLE_SOURCE_CONFLICT = "role_source_conflict"
    ROLE_SOURCE_PRECEDENCE_UNPROVEN = "role_source_precedence_unproven"
    APP_FILTER_EMPTY_UNPROVEN = "app_filter_empty_unproven"
    APP_FILTER_UNMAPPED = "app_filter_unmapped"
    GROUP_FILTER_UNSUPPORTED = "group_filter_unsupported"
    GROUP_FILTER_TIMEOUT = "group_filter_timeout"
    GROUP_FILTER_MATCH_UNPROVEN = "group_filter_match_unproven"
    ROLE_VALUE_PATTERN_UNSUPPORTED = "role_value_pattern_unsupported"
    # After the settings reasons above (what Okta may test) and before data
    # reasons (what was collected): item 4 of the record is a rule, not a gap.
    GROUP_MAPPING_SCOPE_UNPROVEN = "group_mapping_scope_unproven"
    GROUP_MEMBERSHIP_INCOMPLETE = "group_membership_incomplete"
    GROUP_ROLE_DEFAULT_UNPROVEN = "group_role_default_unproven"
    IDENTITY_PROVIDER_ARN_UNUSABLE = "identity_provider_arn_unusable"
    ROLE_NAME_NOT_PLAIN = "role_name_not_plain"
    ROLE_PAIR_RULE_UNPROVEN = "role_pair_rule_unproven"
    ROLE_SESSION_NAME_SOURCE_UNPROVEN = "role_session_name_source_unproven"


@dataclass(frozen=True)
class RoleValue:
    """Values for one user and the reason they can lack values, if any."""

    match_values: tuple[str, ...]
    reason: IncompleteReason | None


def first_reason(reasons: Iterable[IncompleteReason]) -> IncompleteReason | None:
    """Return the reason with the highest precedence, or None for no reason."""

    found = set(reasons)
    return next((reason for reason in IncompleteReason if reason in found), None)


# Native fields: record "Native fields", `settings.app.*` of the application.
@dataclass(frozen=True)
class AwsFederationSettings:
    identity_provider_arn: str | None
    join_all_roles: bool
    use_group_mapping: bool
    app_filter: str | None
    group_filter: str | None
    role_value_pattern: str | None

    @classmethod
    def from_app_settings(
        cls, settings: Mapping[str, Any] | None
    ) -> AwsFederationSettings:
        settings = settings or {}

        def text(key: str) -> str | None:
            value = settings.get(key)
            return value.strip() or None if isinstance(value, str) else None

        return cls(
            identity_provider_arn=text("identityProviderArn"),
            join_all_roles=settings.get("joinAllRoles") is True,
            use_group_mapping=settings.get("useGroupMapping") is True,
            app_filter=text("appFilter"),
            group_filter=text("groupFilter"),
            role_value_pattern=text("roleValuePattern"),
        )


@dataclass(frozen=True)
class GroupRef:
    """A collected group. `source_app_name` is set for a group from an application."""

    id: str
    name: str
    type: str | None
    source_app_name: str | None


@dataclass(frozen=True)
class GroupAssignment:
    """An assignment of a group to the application, with its role fields."""

    group_id: str
    role: str | None
    saml_roles: tuple[str, ...]


@dataclass(frozen=True)
class MappedGroup:
    """A group that can give a Role value through group mapping.

    `value` is set when the match is proven. `reason` is set when it is not.
    """

    group_id: str
    value: str | None
    reason: IncompleteReason | None


@dataclass(frozen=True)
class GroupMappingPlan:
    """Groups that can give a value. `reason` is set when no group can be tested."""

    groups: tuple[MappedGroup, ...] = ()
    reason: IncompleteReason | None = None


@dataclass(frozen=True)
class AwsRoleSources:
    """Everything outside the assignment's own profile that decides the Role value."""

    settings: AwsFederationSettings
    group_assignments: tuple[GroupAssignment, ...] | None = None
    group_mapping: GroupMappingPlan | None = None


# --- Roles on an assignment (Design rule 2; record "Join all roles") ---------

_ARN_PARTITION = r"aws(?:-[a-z]+)*"
_PROVIDER_ARN = re.compile(
    rf"arn:({_ARN_PARTITION}):iam::(\d{{12}}):saml-provider/[\w+=,.@-]+", re.ASCII
)
_ROLE_ARN = re.compile(
    rf"arn:{_ARN_PARTITION}:iam::\d{{12}}:role/(?:[\w+=.@-]+/)*[\w+=.@-]{{1,64}}",
    re.ASCII,
)
# A plain IAM role name. A comma is left out because it separates the two ARNs.
_PLAIN_ROLE_NAME = re.compile(r"[\w+=.@-]{1,64}", re.ASCII)


def _role_names(roles: object, role: object) -> tuple[list[str], bool]:
    """Return the names of `samlRoles`, else of `role`, and whether one is not text."""

    values = roles if isinstance(roles, list) else [roles] if roles else []
    if not values and role:
        values = [role]
    names = [value.strip() for value in values if isinstance(value, str)]
    return [name for name in names if name], len(names) != len(values)


def _assignment_values(
    settings: AwsFederationSettings,
    profile: Mapping[str, Any],
    assignments: tuple[GroupAssignment, ...] | None,
    is_member: MembershipCheck | None,
) -> tuple[list[str], set[IncompleteReason]]:
    """Pairs for the roles on the user's assignment, and on groups when joined.

    Okta applies the group priority, or "Combine values across groups", to the
    profile of the application user before this reads it (record, group priority).
    """

    reasons: set[IncompleteReason] = set()
    names, not_text = _role_names(profile.get("samlRoles"), profile.get("role"))
    if not_text:
        reasons.add(IncompleteReason.ROLE_NAME_NOT_PLAIN)
    if settings.join_all_roles:
        if assignments is None:
            reasons.add(IncompleteReason.GROUP_MEMBERSHIP_INCOMPLETE)
        for assignment in assignments or ():
            member = is_member("id", assignment.group_id) if is_member else None
            if member is None:
                reasons.add(IncompleteReason.GROUP_MEMBERSHIP_INCOMPLETE)
            elif member and assignment.saml_roles:
                names.extend(assignment.saml_roles)
            elif member and assignment.role:
                # The role of a group without SAML User Roles is not documented
                # for "Join all roles".
                reasons.add(IncompleteReason.GROUP_ROLE_DEFAULT_UNPROVEN)

    provider = _PROVIDER_ARN.fullmatch(settings.identity_provider_arn or "")
    plain = [name for name in dict.fromkeys(names) if _PLAIN_ROLE_NAME.fullmatch(name)]
    if len(plain) != len(set(names)):
        reasons.add(IncompleteReason.ROLE_NAME_NOT_PLAIN)
    if not provider:
        if plain:
            reasons.add(IncompleteReason.IDENTITY_PROVIDER_ARN_UNUSABLE)
        return [], reasons
    partition, account = provider.groups()
    pairs = [
        f"{provider.group(0)},arn:{partition}:iam::{account}:role/{name}"
        for name in plain
    ]
    if pairs:
        # Item 1 of the record: how Okta makes the pair is not proven.
        reasons.add(IncompleteReason.ROLE_PAIR_RULE_UNPROVEN)
    return pairs, reasons


# --- Group mapping (Design rule 3) -------------------------------------------

_NAMED_GROUPS = {"(?{{role}}": "(?P<role>", "(?{{accountid}}": "(?P<accountid>"}
_PLACEHOLDER = re.compile(r"\(\?\{\{(?:role|accountid)\}\}")
# Tokens that mean the same in Java and in Python: an escaped punctuation
# literal, \w \d \s \S, a quantifier, a group start, an alternative, or an anchor.
_ESCAPE = re.compile(r"\\(?:[wdsS]|[^\w\s])")
_QUANTIFIER = re.compile(r"[?*+]|\{\d+(?:,\d*)?\}")
_CLASS = re.compile(r"\[\^?(?:\\(?:[wdsS]|[^\w\s])|[^\\\[\]&])+\]")
_LITERAL = re.compile(r"[^\\.()\[\]{}*+?|^$]")
_ATOMS = (_ESCAPE, _CLASS, _LITERAL)
_SYNTAX = re.compile(r"\((?!\?)|\(\?:|\)|\||\^|\$")


# Longest time for one Group Filter match. A documented filter on a 255
# character name takes microseconds, so this is far above a normal match. A
# filter that can backtrack for long (for example side by side repeats such as
# \w*\w*\w*) is cut off here, and the whole plan becomes incomplete.
_GROUP_FILTER_TIMEOUT_SECONDS = 0.25
# The `re`-compatible behavior (V0). ASCII gives the Java default meaning of
# \w, \d, \s and of case folding.
_FILTER_FLAGS = regex.V0 | regex.ASCII


def _supported_group_filter(expression: str) -> str | None:
    """Return the Python form of a Group Filter, or None for unsupported syntax.

    Only the syntax of the Design is accepted, so a name tested here gives the
    same result in Okta's Java engine. Both named groups must exist, and no other.
    """

    rewritten: list[str] = []
    position = 0
    after_atom = False  # a quantifier needs an atom before it
    # One flag for each open group: it holds a quantifier or an alternative.
    open_groups: list[bool] = []
    closed_risky = False  # the group that just closed holds a quantifier or "|"
    while position < len(expression):
        was_closed_risky, closed_risky = closed_risky, False
        token = _PLACEHOLDER.match(expression, position)
        if token:
            if _NAMED_GROUPS[token.group()] in rewritten:
                return None  # `regex` accepts a repeated group name; `re` does not
            rewritten.append(_NAMED_GROUPS[token.group()])
            open_groups.append(False)
            after_atom = False
        elif token := _SYNTAX.match(expression, position):
            text = token.group()
            rewritten.append(text)
            if text == ")":
                if not open_groups:
                    return None
                closed_risky = open_groups.pop()
                if open_groups and closed_risky:
                    open_groups[-1] = True
            elif text.startswith("("):
                open_groups.append(False)
            elif text == "|" and open_groups:
                open_groups[-1] = True
            after_atom = text == ")"
        elif token := _QUANTIFIER.match(expression, position):
            # A quantified group that holds a quantifier or "|" can backtrack
            # without limit, for example (\w+)+.
            if not after_atom or was_closed_risky:
                return None
            rewritten.append(token.group())
            if open_groups:
                open_groups[-1] = True
            after_atom = False
        else:
            token = next(
                (m for atom in _ATOMS if (m := atom.match(expression, position))), None
            )
            # Python warns that these doubled characters in a class will change.
            if token is None or (
                token.group().startswith("[")
                and any(op in token.group() for op in ("--", "||", "~~"))
            ):
                return None
            rewritten.append(token.group())
            after_atom = True
        position = token.end()
    python_form = "".join(rewritten)
    try:
        compiled = regex.compile(python_form, _FILTER_FLAGS)
    except regex.error:
        return None
    # Exactly the two named groups: a literal "(?P<role>" is not one.
    return python_form if set(compiled.groupindex) == {"role", "accountid"} else None


def _role_value(pattern: str | None, account: str, role: str) -> str | None:
    """Apply the Role Value Pattern. The result must be one provider and one role ARN."""

    if not pattern or "${accountid}" not in pattern or "${role}" not in pattern:
        return None
    value = pattern.replace("${accountid}", account).replace("${role}", role)
    arns = value.split(",")
    if len(arns) != 2:
        return None
    provider, role_arn = sorted(arns, key=lambda arn: ":role/" in arn)
    if _PROVIDER_ARN.fullmatch(provider) and _ROLE_ARN.fullmatch(role_arn):
        return value
    return None


def _mapped_group(
    group: GroupRef,
    filters: tuple[regex.Pattern[str], regex.Pattern[str]],
    pattern: str | None,
) -> MappedGroup | None:
    """Test one group name in the four ways Okta leaves open (record, item 3).

    The ways are full or part of the name, and case-sensitive or not. Return None
    for a name that no way matches. Raise TimeoutError when a match takes too long.
    """

    matches = [
        test(group.name, timeout=_GROUP_FILTER_TIMEOUT_SECONDS)
        for compiled in filters
        for test in (compiled.fullmatch, compiled.search)
    ]
    if not any(matches):
        return None
    captures = {(m["role"], m["accountid"]) if m else None for m in matches}
    capture = captures.pop()
    # The ways disagree, or a branch left a named group unset.
    if captures or capture is None or None in capture:
        return MappedGroup(group.id, None, IncompleteReason.GROUP_FILTER_MATCH_UNPROVEN)
    role, account = capture
    value = _role_value(pattern, account, role)
    if value is None:
        return MappedGroup(
            group.id, None, IncompleteReason.ROLE_VALUE_PATTERN_UNSUPPORTED
        )
    return MappedGroup(group.id, value, None)


def _permitted_by_app_filter(group: GroupRef, app_filter: str) -> bool | None:
    """Whether the App Filter lets Okta test this group. None means not known."""

    if group.type == "BUILT_IN":
        return None if app_filter == "okta" else False
    if app_filter == "okta":
        return group.type == "OKTA_GROUP"
    if group.type == "APP_GROUP" and group.source_app_name is None:
        return None  # the source application is not collected
    return group.source_app_name == app_filter


def plan_group_mapping(
    settings: AwsFederationSettings,
    groups: Iterable[GroupRef],
    application_names: frozenset[str],
) -> GroupMappingPlan:
    """Find the groups whose names can give a Role value (rule 3, steps 1 to 4)."""

    if not settings.app_filter:
        return GroupMappingPlan(reason=IncompleteReason.APP_FILTER_EMPTY_UNPROVEN)
    if settings.app_filter != "okta" and settings.app_filter not in application_names:
        return GroupMappingPlan(reason=IncompleteReason.APP_FILTER_UNMAPPED)
    python_form = _supported_group_filter(settings.group_filter or "")
    if python_form is None:
        return GroupMappingPlan(reason=IncompleteReason.GROUP_FILTER_UNSUPPORTED)
    filters = (
        regex.compile(python_form, _FILTER_FLAGS),
        regex.compile(python_form, _FILTER_FLAGS | regex.IGNORECASE),
    )
    mapped: list[MappedGroup] = []
    for group in groups:
        permitted = _permitted_by_app_filter(group, settings.app_filter)
        if permitted is False:
            continue
        try:
            found = _mapped_group(group, filters, settings.role_value_pattern)
        except TimeoutError:
            # Stop at the first timeout: the plan does not depend on which
            # group timed out, and it costs one timeout for each application.
            return GroupMappingPlan(reason=IncompleteReason.GROUP_FILTER_TIMEOUT)
        if found is None:
            continue
        if permitted is None:  # a group of unknown source that could match
            found = MappedGroup(group.id, None, IncompleteReason.APP_FILTER_UNMAPPED)
        mapped.append(found)
    return GroupMappingPlan(tuple(mapped))


def _mapped_values(
    plan: GroupMappingPlan | None,
    assignments: tuple[GroupAssignment, ...] | None,
    is_member: MembershipCheck | None,
) -> tuple[list[str], set[IncompleteReason]]:
    """Values of the user's matching groups.

    Item 4 of the record: Okta does not say if it tests all groups of the user
    or only groups assigned to the application. A value from a group with no
    assignment is therefore incomplete.
    """

    if plan is None:
        return [], {IncompleteReason.GROUP_MEMBERSHIP_INCOMPLETE}
    if plan.reason:
        return [], {plan.reason}
    values: list[str] = []
    reasons: set[IncompleteReason] = set()
    for group in plan.groups:
        member = is_member("id", group.group_id) if is_member else None
        if member is None:
            reasons.add(IncompleteReason.GROUP_MEMBERSHIP_INCOMPLETE)
        elif member and group.value:
            values.append(group.value)
            if assignments is None or group.group_id not in {
                assignment.group_id for assignment in assignments
            }:
                reasons.add(IncompleteReason.GROUP_MAPPING_SCOPE_UNPROVEN)
        elif member and group.reason:
            reasons.add(group.reason)
    return values, reasons


def role_value(
    profile: Mapping[str, Any] | None,
    sources: AwsRoleSources,
    is_member: MembershipCheck | None,
) -> RoleValue:
    """Combine the sources of the `Role` attribute for one user (rules 2 and 3)."""

    pairs, reasons = _assignment_values(
        sources.settings, profile or {}, sources.group_assignments, is_member
    )
    mapped: list[str] = []
    if sources.settings.use_group_mapping:
        mapped, mapping_reasons = _mapped_values(
            sources.group_mapping, sources.group_assignments, is_member
        )
        reasons |= mapping_reasons
        if pairs and mapped:
            # Rule 3, step 5: Okta does not document which source wins.
            reasons.add(IncompleteReason.ROLE_SOURCE_PRECEDENCE_UNPROVEN)
    return RoleValue(tuple(dict.fromkeys(pairs + mapped)), first_reason(reasons))


def aws_role_sources(
    lookup: Any, app_id: str, app_settings: Mapping[str, Any] | None
) -> AwsRoleSources:
    """Read the group data for an application's Role values from a lookup.

    A lookup without the group methods gives None, which makes the value
    incomplete.
    """

    settings = AwsFederationSettings.from_app_settings(app_settings)
    assignments = getattr(lookup, "aws_group_assignments", None)
    plan = getattr(lookup, "aws_group_mapping_plan", None)
    return AwsRoleSources(
        settings,
        assignments(app_id) if callable(assignments) else None,
        plan(settings) if settings.use_group_mapping and callable(plan) else None,
    )
