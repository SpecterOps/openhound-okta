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
import string
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

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

    # "Item N" is an item of the record's "Not documented" list. "Rule N" is a
    # rule of Issue #88 that is not one of the seven items.
    ROLE_SOURCE_CONFLICT = "role_source_conflict"  # rule 1
    ROLE_SOURCE_PRECEDENCE_UNPROVEN = "role_source_precedence_unproven"  # item 2
    APP_FILTER_EMPTY_UNPROVEN = "app_filter_empty_unproven"  # item 5
    APP_FILTER_UNMAPPED = "app_filter_unmapped"  # rule 3, step 1
    GROUP_FILTER_UNSUPPORTED = "group_filter_unsupported"  # rule 3, step 2
    GROUP_FILTER_MATCH_UNPROVEN = "group_filter_match_unproven"  # item 3
    ROLE_VALUE_PATTERN_UNSUPPORTED = "role_value_pattern_unsupported"  # rule 3, step 4
    # After the settings reasons above (what Okta may test) and before data
    # reasons (what was collected): item 4 is a rule, not a gap.
    GROUP_MAPPING_SCOPE_UNPROVEN = "group_mapping_scope_unproven"  # item 4
    GROUP_MEMBERSHIP_INCOMPLETE = "group_membership_incomplete"  # rule 2, step 5
    GROUP_ROLE_DEFAULT_UNPROVEN = "group_role_default_unproven"  # rule 2, step 3
    IDENTITY_PROVIDER_ARN_UNUSABLE = "identity_provider_arn_unusable"  # rule 2, step 5
    ROLE_NAME_NOT_PLAIN = "role_name_not_plain"  # item 7
    ROLE_PAIR_RULE_UNPROVEN = "role_pair_rule_unproven"  # item 1
    ROLE_SESSION_NAME_SOURCE_UNPROVEN = "role_session_name_source_unproven"  # item 6


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


# The role and account ID that a Group Filter takes from one group name.
Capture = tuple[str, str]


@dataclass(frozen=True)
class GroupNameMatch:
    """What the Group Filter did with one group name, from the DuckDB match.

    `captures` has one entry for each way Okta may match (record, item 3): part
    of the name and the full name, each with and without letter case. An entry
    is None when that way does not match. `unprovable` is set when DuckDB (RE2)
    and Okta (Java) can differ for this name, so no result can be trusted.
    """

    group: GroupRef
    captures: tuple[Capture | None, ...]
    unprovable: bool


@dataclass(frozen=True)
class GroupAssignment:
    """An assignment of a group to the application, with its role fields."""

    group_id: str
    # The native values, cleaned like the roles of a user (`_clean_names`).
    role: object
    saml_roles: object


@dataclass(frozen=True)
class MappedGroup:
    """A group that can give a Role value through group mapping.

    `value` is set when the match is proven. `reason` is set when it is not.
    `assigned` is set when the group has an assignment to the application.
    """

    group_id: str
    value: str | None
    reason: IncompleteReason | None
    assigned: bool = False


@dataclass(frozen=True)
class GroupMappingPlan:
    """Groups that can give a value. `reason` is set when no group can be tested."""

    groups: tuple[MappedGroup, ...] = ()
    reason: IncompleteReason | None = None


@dataclass(frozen=True)
class AwsUserGroups:
    """The group data of one user of the application, from the `preproc` table.

    `assigned` and `mapped` hold only groups in which the user is a member with
    proof. A group whose members were not all collected is not proven for any
    user, so it makes the whole application `*_unproven`. A user whose row
    cannot be read has `UNREADABLE_GROUPS`.
    """

    assigned: tuple[GroupAssignment, ...] = ()
    mapped: tuple[MappedGroup, ...] = ()
    assigned_unproven: bool = False
    mapped_unproven: bool = False
    # Set when the settings give no group that can be tested (the plan reason).
    mapping_reason: IncompleteReason | None = None


UNREADABLE_GROUPS = AwsUserGroups(assigned_unproven=True, mapped_unproven=True)


@dataclass(frozen=True)
class AwsRoleSources:
    """Everything outside the assignment's own profile that decides the Role value."""

    settings: AwsFederationSettings
    groups: AwsUserGroups = AwsUserGroups()


# --- Roles on an assignment (Design rule 2; record "Join all roles") ---------

_ARN_PARTITION = r"aws(?:-[a-z]+)*"
_PROVIDER_ARN = re.compile(
    rf"arn:({_ARN_PARTITION}):iam::(\d{{12}}):saml-provider/[\w+=.@-]+", re.ASCII
)
_ROLE_ARN = re.compile(
    rf"arn:{_ARN_PARTITION}:iam::\d{{12}}:role/(?:[\w+=.@-]+/)*[\w+=.@-]{{1,64}}",
    re.ASCII,
)
# A plain IAM role name. A comma is left out because it separates the two ARNs.
_PLAIN_ROLE_NAME = re.compile(r"[\w+=.@-]{1,64}", re.ASCII)


def _clean_names(values: object) -> tuple[list[str], bool]:
    """Return the stripped, non-empty text values, and whether one is not text."""

    items = values if isinstance(values, (list, tuple)) else [values] if values else []
    names = [item.strip() for item in items if isinstance(item, str)]
    return [name for name in names if name], len(names) != len(items)


def _role_names(roles: object, role: object) -> tuple[list[str], bool]:
    """Return the names of `samlRoles`, else of `role`, and whether one is not text."""

    names, not_text = _clean_names(roles)
    if not names:
        names, role_not_text = _clean_names(role)
        not_text = not_text or role_not_text
    return names, not_text


def _assignment_values(
    settings: AwsFederationSettings,
    profile: Mapping[str, Any],
    groups: AwsUserGroups,
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
        if groups.assigned_unproven:
            reasons.add(IncompleteReason.GROUP_MEMBERSHIP_INCOMPLETE)
        for assignment in groups.assigned:
            group_names, not_text = _clean_names(assignment.saml_roles)
            names.extend(group_names)
            if not_text:
                reasons.add(IncompleteReason.ROLE_NAME_NOT_PLAIN)
            if not group_names and _clean_names(assignment.role)[0]:
                # The role of a group without SAML User Roles is not
                # documented for "Join all roles".
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

_NAMED_GROUPS = {"(?{{role}}": "role", "(?{{accountid}}": "accountid"}
_PLACEHOLDER = re.compile(r"\(\?\{\{(?:role|accountid)\}\}")
# Tokens that mean the same in Java and in RE2, the engine of DuckDB: an escaped
# punctuation literal, \w \d \s \S, a quantifier, a group start, an alternative,
# or an anchor. The filter must be ASCII (see `_supported_group_filter`).
_SET_ESCAPES = frozenset({r"\w", r"\d", r"\s", r"\S"})
_PUNCTUATION = re.escape(string.punctuation.replace("_", ""))
_ESCAPE = re.compile(rf"\\(?:[wdsS]|[{_PUNCTUATION}])")
# Repeat counts have at most 3 digits: Okta group names have at most 255 characters.
_QUANTIFIER = re.compile(r"[?*+]|\{\d{1,3}(?:,\d{0,3})?\}")
_CLASS = re.compile(rf"\[\^?(?:\\(?:[wdsS]|[{_PUNCTUATION}])|[^\\\[\]&])+\]")
_LITERAL = re.compile(r"[^\\.()\[\]{}*+?|^$]")
_ATOMS = (_ESCAPE, _CLASS, _LITERAL)
_SYNTAX = re.compile(r"\((?!\?)|\(\?:|\)|\||\^|\$")
_CLASS_ITEM = re.compile(r"\\.|.")
# Java `\s` has the vertical tab and RE2 `\s` has not. The POSIX class of RE2
# has it, so it is written for `\s` and `\S`.
_RE2_SPACE = {r"\s": "[:space:]", r"\S": "[:^space:]"}
_MAX_FILTER_LENGTH = 512
_MAX_GROUP_DEPTH = 8


def _class_is_shared(text: str) -> bool:
    r"""Whether a character class means the same in Java and in RE2.

    A doubled `--`, `||` or `~~` is a set operation in some regex engines. A
    range with `\w`, `\d`, `\s` or `\S` as an end, such as `[a-\w]`, is an error
    in RE2 and probably in Java. A leading or trailing `-` is fine.
    """

    if any(operator in text for operator in ("--", "||", "~~")):
        return False
    items = _CLASS_ITEM.findall(text[1:-1].removeprefix("^"))
    return not any(
        item == "-"
        and 0 < index < len(items) - 1
        and (items[index - 1] in _SET_ESCAPES or items[index + 1] in _SET_ESCAPES)
        for index, item in enumerate(items)
    )


def _re2_atom(text: str) -> str:
    """Write an accepted escape or character class in RE2 form."""

    if text.startswith("["):
        negation = "^" if text.startswith("[^") else ""
        items = _CLASS_ITEM.findall(text[1:-1].removeprefix("^"))
        return f"[{negation}{''.join(_RE2_SPACE.get(item, item) for item in items)}]"
    return f"[{_RE2_SPACE[text]}]" if text in _RE2_SPACE else text


@dataclass(frozen=True)
class GroupFilter:
    """A Group Filter in RE2 form, ready for DuckDB.

    The only capture groups of `pattern` are the two named ones. DuckDB names
    the captures by position, so `capture_names` lists them in the order they
    appear in the pattern.
    """

    pattern: str
    capture_names: tuple[str, ...]
    end_anchored: bool


def _supported_group_filter(expression: str) -> GroupFilter | None:
    """Return the RE2 form of a Group Filter, or None for unsupported syntax.

    Only the syntax of the Design is accepted, so a name tested in DuckDB gives
    the same result in Okta's Java engine. Both named groups must exist, once
    each, and no other group is named. The filter is ASCII: RE2 folds letter
    case for all of Unicode and Java for ASCII only, so a non-ASCII letter in a
    filter would match differently with letter case off. A name that DuckDB
    cannot compile (for example a size limit) is found when it runs.
    """

    if len(expression) > _MAX_FILTER_LENGTH or not expression.isascii():
        return None
    rewritten: list[str] = []
    named: list[str] = []
    position = 0
    after_atom = False  # a quantifier needs an atom before it
    # One flag for each open group: it holds a quantifier or an alternative.
    open_groups: list[bool] = []
    closed_risky = False  # the group that just closed holds a quantifier or "|"
    while position < len(expression):
        was_closed_risky, closed_risky = closed_risky, False
        token = _PLACEHOLDER.match(expression, position)
        if token:
            name = _NAMED_GROUPS[token.group()]
            if name in named:
                return None
            named.append(name)
            rewritten.append(f"(?P<{name}>")
            open_groups.append(False)
            after_atom = False
        elif token := _SYNTAX.match(expression, position):
            text = token.group()
            # Only the two named groups capture, so DuckDB gives them by position.
            rewritten.append("(?:" if text == "(" else text)
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
            if token is None or (
                token.group().startswith("[") and not _class_is_shared(token.group())
            ):
                return None
            rewritten.append(_re2_atom(token.group()))
            after_atom = True
        if len(open_groups) > _MAX_GROUP_DEPTH:
            return None
        position = token.end()
    if open_groups or set(named) != set(_NAMED_GROUPS.values()):
        return None
    return GroupFilter("".join(rewritten), tuple(named), "$" in expression)


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


def _mapped_group(match: GroupNameMatch, pattern: str | None) -> MappedGroup | None:
    """Judge one group name from its four matches (record, item 3).

    The ways are full or part of the name, and case-sensitive or not. Return
    None for a name that no way matches.
    """

    group_id = match.group.id
    if match.unprovable:
        return MappedGroup(group_id, None, IncompleteReason.GROUP_FILTER_MATCH_UNPROVEN)
    captures = set(match.captures)
    capture = captures.pop()
    if not captures and capture is None:
        return None
    # The ways disagree, or a group is empty. DuckDB gives an empty text for
    # a named group that did not take part in the match, so it cannot tell
    # that from an empty capture.
    if captures or capture is None or "" in capture:
        return MappedGroup(group_id, None, IncompleteReason.GROUP_FILTER_MATCH_UNPROVEN)
    role, account = capture
    value = _role_value(pattern, account, role)
    if value is None:
        return MappedGroup(
            group_id, None, IncompleteReason.ROLE_VALUE_PATTERN_UNSUPPORTED
        )
    return MappedGroup(group_id, value, None)


def _permitted_by_app_filter(group: GroupRef, app_filter: str) -> bool | None:
    """Whether the App Filter lets Okta test this group. None means not known."""

    if group.type == "BUILT_IN":
        return None if app_filter == "okta" else False
    if app_filter == "okta":
        return group.type == "OKTA_GROUP"
    if group.type == "APP_GROUP" and group.source_app_name is None:
        return None  # the source application is not collected
    return group.source_app_name == app_filter


# Finds the group names that a Group Filter can match. None means DuckDB
# rejected the pattern.
GroupFilterMatcher = Callable[[GroupFilter], list[GroupNameMatch] | None]


def plan_group_mapping(
    settings: AwsFederationSettings,
    application_names: frozenset[str],
    find_matches: GroupFilterMatcher,
) -> GroupMappingPlan:
    """Find the groups whose names can give a Role value (rule 3, steps 1 to 4)."""

    if not settings.app_filter:
        return GroupMappingPlan(reason=IncompleteReason.APP_FILTER_EMPTY_UNPROVEN)
    if settings.app_filter != "okta" and settings.app_filter not in application_names:
        return GroupMappingPlan(reason=IncompleteReason.APP_FILTER_UNMAPPED)
    group_filter = _supported_group_filter(settings.group_filter or "")
    matches = find_matches(group_filter) if group_filter else None
    if matches is None:
        return GroupMappingPlan(reason=IncompleteReason.GROUP_FILTER_UNSUPPORTED)
    mapped: list[MappedGroup] = []
    for match in matches:
        permitted = _permitted_by_app_filter(match.group, settings.app_filter)
        if permitted is False:
            continue
        found = _mapped_group(match, settings.role_value_pattern)
        if found is None:
            continue
        if permitted is None:  # a group of unknown source that could match
            found = MappedGroup(
                found.group_id, None, IncompleteReason.APP_FILTER_UNMAPPED
            )
        mapped.append(found)
    return GroupMappingPlan(tuple(mapped))


def _mapped_values(groups: AwsUserGroups) -> tuple[list[str], set[IncompleteReason]]:
    """Values of the user's matching groups.

    Item 4 of the record: Okta does not say if it tests all groups of the user
    or only groups assigned to the application. A value from a group with no
    assignment is therefore incomplete.
    """

    if groups.mapping_reason:
        return [], {groups.mapping_reason}
    values: list[str] = []
    reasons: set[IncompleteReason] = set()
    if groups.mapped_unproven:
        reasons.add(IncompleteReason.GROUP_MEMBERSHIP_INCOMPLETE)
    for group in groups.mapped:
        if group.value:
            values.append(group.value)
            if not group.assigned:
                reasons.add(IncompleteReason.GROUP_MAPPING_SCOPE_UNPROVEN)
        elif group.reason:
            reasons.add(group.reason)
    return values, reasons


def role_value(profile: Mapping[str, Any] | None, sources: AwsRoleSources) -> RoleValue:
    """Combine the sources of the `Role` attribute for one user (rules 2 and 3)."""

    pairs, reasons = _assignment_values(sources.settings, profile or {}, sources.groups)
    mapped: list[str] = []
    if sources.settings.use_group_mapping:
        mapped, mapping_reasons = _mapped_values(sources.groups)
        reasons |= mapping_reasons
        if pairs and mapped:
            # Rule 3, step 5: Okta does not document which source wins.
            reasons.add(IncompleteReason.ROLE_SOURCE_PRECEDENCE_UNPROVEN)
    return RoleValue(tuple(dict.fromkeys(pairs + mapped)), first_reason(reasons))


def aws_role_sources(
    lookup: Any, app_id: str, user_id: str, app_settings: Mapping[str, Any] | None
) -> AwsRoleSources:
    """Read the group data of one user for the Role value from a lookup.

    A lookup without the group method gives `UNREADABLE_GROUPS`, which makes the
    value incomplete.
    """

    settings = AwsFederationSettings.from_app_settings(app_settings)
    read = getattr(lookup, "aws_user_groups", None)
    groups = read(app_id, user_id) if callable(read) else None
    return AwsRoleSources(settings, groups or UNREADABLE_GROUPS)
