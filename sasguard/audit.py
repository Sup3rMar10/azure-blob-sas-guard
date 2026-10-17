"""Read a SAS token (or a URL carrying one) and say what is wrong with it, without ever echoing its signature."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlsplit

from .policy import READ_PERMS, WRITE_PERMS, Policy

ALLOWED = READ_PERMS | WRITE_PERMS


class NotASas(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    id: str
    severity: str  # "error" fails the audit, "warn" only prints
    message: str

    def __str__(self) -> str:
        return f"[{self.severity}] {self.id}: {self.message}"


def parse_query(text: str) -> dict[str, str]:
    """The parameters of a SAS from a full URL or a bare query string. Keys are lower-cased; the first value wins."""
    query = urlsplit(text.strip()).query if "?" in text or "://" in text else text.strip().lstrip("?")
    params: dict[str, str] = {}
    for k, v in parse_qsl(query, keep_blank_values=True):
        params.setdefault(k.lower(), v)
    if "sig" not in params:
        raise NotASas("there is no sig parameter, so this is not a SAS")
    return params


def parse_time(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%MZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def audit(token: str, now: datetime | None = None, policy: Policy | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    policy = policy or Policy()
    p = parse_query(token)
    out: list[Finding] = []
    perms = set(p.get("sp", ""))
    writes = bool(perms & WRITE_PERMS)

    # --- when it is valid ------------------------------------------------------------------------------------------
    expiry = parse_time(p["se"]) if "se" in p else None
    if "se" not in p and "si" not in p:
        out.append(Finding("SAS-001", "error", "there is no expiry (se) and no stored access policy to supply one: the token never expires"))
    elif "se" not in p:
        out.append(Finding("SAS-008", "warn", f"the expiry lives in the stored access policy {p['si']!r}; check that policy as well"))
    elif expiry is None:
        out.append(Finding("SAS-001", "error", f"the expiry {p['se']!r} cannot be read"))
    else:
        start = parse_time(p["st"]) if "st" in p else None
        begin = start or now
        limit = policy.max_write_ttl if writes else policy.max_read_ttl
        # The start is backdated by the policy's skew on purpose, so a token that is exactly `limit` long from now is fine.
        allowance = limit + (policy.skew if start else timedelta(0))
        if expiry - begin > allowance:
            out.append(Finding("SAS-002", "error", f"valid for {expiry - begin}, longer than the {limit} allowed for {'write' if writes else 'read'} access"))
        if expiry < now:
            out.append(Finding("SAS-003", "warn", "the token has expired (if it was exposed, the exposure is harmless now but worth a look)"))

    # --- what it can do ---------------------------------------------------------------------------------------------
    extra = perms - ALLOWED
    if extra:
        out.append(Finding("SAS-004", "error", f"permission(s) {''.join(sorted(extra))} go beyond read, list, create, write and add (delete and friends)"))
    if "ss" in p or "srt" in p:
        out.append(Finding("SAS-009", "error", "this is an account-level SAS (ss/srt): it reaches whole services, not one blob"))
    scope = p.get("sr", "")
    if scope in {"c", "d"}:
        out.append(Finding("SAS-011", "warn", "container or directory scope reaches every blob beneath it; prefer a blob-scope SAS"))
        if writes:
            out.append(Finding("SAS-010", "error", "a container-scope SAS that can write"))

    # --- where it can be used ---------------------------------------------------------------------------------------
    if p.get("spr", "").lower() != "https":
        out.append(Finding("SAS-005", "error", "https is not required (spr is missing or allows http): the token can be sent in the clear"))
    if "sip" not in p:
        out.append(Finding("SAS-006", "warn", "no IP restriction (sip)"))
        if writes and policy.require_ip_for_write:
            out.append(Finding("SAS-012", "error", "a SAS that can write has no IP restriction"))

    # --- how it can be taken back ------------------------------------------------------------------------------------
    if "skoid" not in p:
        out.append(Finding("SAS-007", "warn", "signed with the account key, not a user delegation key: only rotating the key (which breaks every other SAS) revokes it"))
    if "si" not in p and "skoid" not in p:  # a user delegation SAS cannot use a stored access policy; its key and short life are its limits
        out.append(Finding("SAS-013", "warn", "no stored access policy, so it cannot be revoked before it expires"))
    return out


def has_errors(findings: list[Finding]) -> bool:
    return any(f.severity == "error" for f in findings)


RULES = {
    "SAS-001": "no expiry", "SAS-002": "lifetime too long", "SAS-003": "already expired (warning)", "SAS-004": "permissions beyond read/list/create/write/add",
    "SAS-005": "https not required", "SAS-006": "no IP restriction (warning)", "SAS-007": "signed with the account key (warning)",
    "SAS-008": "expiry only in a stored policy (warning)", "SAS-009": "account-level SAS", "SAS-010": "container-scope SAS that can write",
    "SAS-011": "container or directory scope (warning)", "SAS-012": "write without an IP restriction", "SAS-013": "no stored access policy (warning)",
}
