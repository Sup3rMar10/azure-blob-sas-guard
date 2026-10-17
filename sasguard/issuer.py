"""Issue a SAS only if the policy allows it. Signing uses the Azure SDK; the policy decides whether to sign at all."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from azure.storage.blob import (AccessPolicy, BlobSasPermissions, BlobServiceClient, ContainerSasPermissions, generate_blob_sas,
                                generate_container_sas)

from .policy import Policy, PolicyViolation, check_request


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Token:
    url: str
    query: str
    starts: datetime
    expires: datetime
    permissions: str


def _blob_perms(p: str) -> BlobSasPermissions:
    return BlobSasPermissions(read="r" in p, add="a" in p, create="c" in p, write="w" in p)


def _container_perms(p: str) -> ContainerSasPermissions:
    return ContainerSasPermissions(read="r" in p, list="l" in p, add="a" in p, create="c" in p, write="w" in p)


class SasIssuer:
    """Signs with the storage account KEY. That is the weaker way (see the README): one key signs every SAS, so only
    rotating it revokes a token that has no stored access policy. A user delegation SAS signed through Entra ID is better."""

    def __init__(self, account_name: str, account_key: str, endpoint: str, policy: Policy | None = None,
                 clock: Callable[[], datetime] = utcnow):
        self.account, self.key, self.endpoint = account_name, account_key, endpoint.rstrip("/")
        self.policy, self.clock = policy or Policy(), clock
        self._stored: dict[tuple[str, str], tuple[str, datetime, datetime]] = {}  # (container, id) -> (permissions, start, expiry)

    def _url(self, container: str, blob: str | None, query: str) -> str:
        return f"{self.endpoint}/{container}" + (f"/{blob}" if blob else "") + f"?{query}"

    def blob(self, container: str, blob: str, permissions: str = "r", ttl: timedelta = timedelta(minutes=10), ip: str | None = None) -> Token:
        problems = check_request(permissions, ttl, container_scope=False, has_blob=True, blob=blob, ip=ip, policy=self.policy)
        if problems:
            raise PolicyViolation(problems)
        now = self.clock()
        start, expiry = now - self.policy.skew, now + ttl
        sas = generate_blob_sas(account_name=self.account, container_name=container, blob_name=blob, account_key=self.key,
                                permission=_blob_perms(permissions), expiry=expiry, start=start, ip=ip, protocol="https")
        return Token(self._url(container, blob, sas), sas, start, expiry, permissions)

    def container(self, container: str, permissions: str = "rl", ttl: timedelta = timedelta(minutes=10), ip: str | None = None) -> Token:
        problems = check_request(permissions, ttl, container_scope=True, has_blob=False, blob=None, ip=ip, policy=self.policy)
        if problems:
            raise PolicyViolation(problems)
        now = self.clock()
        start, expiry = now - self.policy.skew, now + ttl
        sas = generate_container_sas(account_name=self.account, container_name=container, account_key=self.key,
                                     permission=_container_perms(permissions), expiry=expiry, start=start, ip=ip, protocol="https")
        return Token(self._url(container, None, sas), sas, start, expiry, permissions)

    # --- stored access policies: the way to revoke a SAS before it expires ------------------------------------------

    def create_stored_policy(self, service: BlobServiceClient, container: str, policy_id: str, permissions: str = "r",
                             ttl: timedelta = timedelta(hours=1)) -> None:
        """Define permissions and lifetime once, on the container. Tokens then carry only the policy's name."""
        problems = check_request(permissions, ttl, container_scope=False, has_blob=True, blob="x", ip="set on each token", policy=self.policy)
        if problems:
            raise PolicyViolation(problems)
        now = self.clock()
        start, expiry = now - self.policy.skew, now + ttl
        client = service.get_container_client(container)
        policies = {si.id: si.access_policy for si in client.get_container_access_policy()["signed_identifiers"]}
        policies[policy_id] = AccessPolicy(permission=_container_perms(permissions), start=start, expiry=expiry)
        client.set_container_access_policy(policies)
        self._stored[(container, policy_id)] = (permissions, start, expiry)

    def blob_via_policy(self, container: str, blob: str, policy_id: str, ip: str | None = None) -> Token:
        """A token that refers to a stored policy. What it may do is checked against what that policy really grants."""
        if (container, policy_id) not in self._stored:
            raise PolicyViolation([f"unknown stored policy {policy_id!r}: create it with this issuer first, so its permissions are known"])
        permissions, start, expiry = self._stored[(container, policy_id)]
        problems = check_request(permissions, expiry - self.clock(), container_scope=False, has_blob=True, blob=blob, ip=ip, policy=self.policy)
        if problems:
            raise PolicyViolation(problems)
        sas = generate_blob_sas(account_name=self.account, container_name=container, blob_name=blob, account_key=self.key,
                                policy_id=policy_id, ip=ip, protocol="https")
        return Token(self._url(container, blob, sas), sas, start, expiry, permissions)

    def revoke(self, service: BlobServiceClient, container: str, policy_id: str) -> None:
        """Delete the stored access policy: every SAS that refers to it stops working at once."""
        client = service.get_container_client(container)
        remaining = {si.id: si.access_policy for si in client.get_container_access_policy()["signed_identifiers"] if si.id != policy_id}
        client.set_container_access_policy(remaining)
        self._stored.pop((container, policy_id), None)
