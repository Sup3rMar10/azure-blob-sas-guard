"""What this organisation allows a shared access signature (SAS) to be, written as code so it can be tested."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

READ_PERMS = set("rl")  # read, list
WRITE_PERMS = set("cwa")  # create, write, add
FORBIDDEN_PERMS = set("dxtimy")  # delete, delete-version, tags, immutability, move, permanent delete: never through a SAS here
ALL_KNOWN = READ_PERMS | WRITE_PERMS | FORBIDDEN_PERMS


class PolicyViolation(Exception):
    def __init__(self, reasons: list[str]):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


@dataclass(frozen=True)
class Policy:
    max_read_ttl: timedelta = timedelta(hours=1)
    max_write_ttl: timedelta = timedelta(minutes=15)
    skew: timedelta = timedelta(minutes=5)  # the start time is backdated by this, so a fast clock somewhere does not make a fresh token "not yet valid"
    allow_container_scope: bool = False  # a container SAS reaches every blob in it
    allow_write: bool = False
    require_ip_for_write: bool = True


def check_request(permissions: str, ttl: timedelta, *, container_scope: bool, has_blob: bool, blob: str | None, ip: str | None,
                  policy: Policy) -> list[str]:
    """Every reason a SAS request is refused, not only the first."""
    problems: list[str] = []
    perms = set(permissions)
    if not permissions:
        problems.append("no permissions requested")
    if len(perms) != len(permissions):
        problems.append("permissions repeat a letter")
    unknown = perms - ALL_KNOWN
    if unknown:
        problems.append(f"unknown permission letter(s): {''.join(sorted(unknown))}")
    forbidden = perms & FORBIDDEN_PERMS
    if forbidden:
        problems.append(f"permission(s) never granted through a SAS: {''.join(sorted(forbidden))} (delete and friends)")
    writes = perms & WRITE_PERMS
    if writes and not policy.allow_write:
        problems.append("write permissions are not allowed by this policy")
    if writes and policy.require_ip_for_write and not ip:
        problems.append("a SAS that can write must be restricted to an IP address or range")
    if container_scope:
        if not policy.allow_container_scope:
            problems.append("a container-scope SAS reaches every blob in the container; use a blob-scope SAS")
        if writes:
            problems.append("a container-scope SAS must not be able to write")
    else:
        if "l" in perms:
            problems.append("list is a container permission; a blob SAS cannot list")
        if not has_blob or not blob:
            problems.append("a blob-scope SAS needs a blob name")
        elif any(c in blob for c in "*?") or blob.endswith("/"):
            problems.append("the blob name must be one exact blob, not a pattern or a folder")
    if ttl <= timedelta(0):
        problems.append("the lifetime must be positive")
    limit = policy.max_write_ttl if writes else policy.max_read_ttl
    if ttl > limit:
        problems.append(f"lifetime {ttl} is longer than the {limit} allowed for {'write' if writes else 'read'} access")
    return problems
