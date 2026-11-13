"""Strict matchers for two narrow forms of Okta attribute expression.

Okta lets a SAML attribute statement list expressions that each test one group
and give one fixed value, for example::

    isMemberOfGroupName("Admins") ? "arn:...:role/admin,arn:...:saml-provider/okta" : null

The second form is one quoted constant. It gives every eligible user that value::

    "arn:...:role/admin,arn:...:saml-provider/okta"

The matchers accept only these forms (see the README section on SAML attribute
values from group expressions). They are not an Okta Expression Language evaluator:
every other text is refused so that the caller can mark the claim value
incomplete.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Literal

GroupSelector = Literal["id", "name"]

# String literals carry no quote or escape. This keeps a comma inside a literal
# (an AWS role/provider pair) from being read as an element separator.
_LITERAL = r'"([^"\\]+)"'
_ELEMENT = (
    rf"\s*isMemberOfGroup(Name)?\(\s*{_LITERAL}\s*\)\s*\?\s*{_LITERAL}\s*:\s*null\s*"
)
# The preprocessed expression joins the native list of expressions with ",".
_EXPRESSION = re.compile(rf"{_ELEMENT}(?:,{_ELEMENT})*")
_ELEMENTS = re.compile(_ELEMENT)
# A whole expression that is one literal. A joined field or function does not
# fullmatch, so it is refused.
_FIXED_VALUE = re.compile(rf"\s*{_LITERAL}\s*")


@dataclass(frozen=True)
class GroupTest:
    """One "user is a member of this group" test and the value it gives."""

    selector: GroupSelector
    group: str
    value: str


# Answers whether the user is in the group: True or False when the collected
# data proves it, None when it cannot (ambiguous group, missing membership).
MembershipCheck = Callable[[GroupSelector, str], bool | None]


def parse_group_tests(expression: str | None) -> tuple[GroupTest, ...] | None:
    """Return the tests of a supported expression, or None for any other text."""

    if not expression or not _EXPRESSION.fullmatch(expression):
        return None
    return tuple(
        GroupTest("name" if by_name else "id", group, value)
        for by_name, group, value in _ELEMENTS.findall(expression)
    )


def parse_fixed_value(expression: str | None) -> str | None:
    """Return the value of a one-constant expression, or None for any other text."""

    if not expression:
        return None
    match = _FIXED_VALUE.fullmatch(expression)
    return match.group(1) if match else None


def evaluate_group_tests(
    tests: tuple[GroupTest, ...], is_member: MembershipCheck | None
) -> list[str] | None:
    """Return the union of the passing tests' values, or None when unproven.

    One test without proof makes the whole result unknown: a known-empty list
    must never hide a role the user could have.
    """

    values: list[str] = []
    for test in tests:
        member = is_member(test.selector, test.group) if is_member else None
        if member is None:
            return None
        if member and test.value not in values:
            values.append(test.value)
    return values
