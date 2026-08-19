from ipaddress import ip_address
import re
from typing import Any
from unicodedata import category
from urllib.parse import urlsplit, urlunsplit


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_GITHUB_SLUG = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,98}[A-Za-z0-9])?$")


def present_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def host_scope(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    if not value or len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return None
    return value


def github_slug(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    return value if _GITHUB_SLUG.fullmatch(value) else None


def host_label(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    return value if _HOST_LABEL.fullmatch(value) else None


def slack_domain(value: Any) -> str | None:
    if not isinstance(value, str) or value != value.strip():
        return None
    labels = value.split(".")
    if len(labels) == 1:
        return value if host_label(labels[0]) else None
    if len(labels) == 2 and labels[1] == "enterprise":
        return value if host_label(labels[0]) else None
    return None


def https_origin(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or any(
            character.isspace() or category(character).startswith("C")
            for character in value
        )
    ):
        return None
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.netloc.endswith(":")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        ip_address(parsed.hostname)
    except ValueError:
        if not host_scope(parsed.hostname):
            return None
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def https_url(value: Any) -> str | None:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or any(
            character.isspace() or category(character).startswith("C")
            for character in value
        )
    ):
        return None
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.netloc.endswith(":")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    try:
        ip_address(parsed.hostname)
    except ValueError:
        if not host_scope(parsed.hostname):
            return None
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
