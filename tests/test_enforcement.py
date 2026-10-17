"""What Azurite really enforces for the tokens this repo issues, and for the weak ones it refuses to issue."""

import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
from azure.storage.blob import BlobSasPermissions, generate_blob_sas

from sasguard import Policy, PolicyViolation, SasIssuer, audit, has_errors

from .conftest import ACCOUNT

MIN = timedelta(minutes=1)


def issuer(a, **kw):
    clock = kw.pop("clock", None)
    return SasIssuer(ACCOUNT, a.key, a.endpoint, kw.pop("policy", None), **({"clock": clock} if clock else {}))


def url_of(a, container, blob="a.txt"):
    return f"{a.endpoint}/{container}/{blob}"


def retarget(url, **changes):
    """The same token with parameters changed (None removes one): signature untouched, so Azure must notice."""
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query))
    for k, v in changes.items():
        if v is None:
            q.pop(k, None)
        else:
            q[k] = v
    return urlunsplit(parts._replace(query=urlencode(q)))


# --- the tokens we issue ------------------------------------------------------------------------------------------------

def test_a_read_token_reads_its_blob_and_nothing_else(az, container):
    t = issuer(az).blob(container, "a.txt")
    assert az.fetch(t.url) == (200, b"AAA")
    assert az.fetch(t.url, "PUT", b"overwritten")[0] == 403
    assert az.fetch(t.url, "DELETE")[0] == 403
    assert az.fetch(issuer(az).blob(container, "a.txt").url.replace("/a.txt?", "/b.txt?"))[0] == 403, "a token for one blob does not open another"
    assert az.fetch(f"{az.endpoint}/{container}?restype=container&comp=list&{t.query}")[0] == 403, "and cannot list the container"
    assert az.fetch(t.url) == (200, b"AAA"), "the blob is untouched"


def test_a_write_token_writes_but_cannot_read_or_delete(az, container):
    iss = issuer(az, policy=Policy(allow_write=True))
    t = iss.blob(container, "new.txt", "cw", ttl=10 * MIN, ip="127.0.0.1")
    assert az.fetch(t.url, "PUT", b"hello")[0] == 201
    assert az.fetch(t.url)[0] == 403
    assert az.fetch(t.url, "DELETE")[0] == 403
    assert az.fetch(iss.blob(container, "new.txt", "r").url) == (200, b"hello")


def test_an_expired_token_is_refused(az, container):
    two_hours_ago = lambda: datetime.now(timezone.utc) - timedelta(hours=2)  # noqa: E731
    t = issuer(az, clock=two_hours_ago).blob(container, "a.txt", ttl=10 * MIN)
    assert t.expires < datetime.now(timezone.utc) and az.fetch(t.url)[0] == 403


def test_the_backdated_start_survives_a_clock_that_runs_fast_and_a_zero_skew_does_not(az, container):
    fast = lambda: datetime.now(timezone.utc) + 2 * MIN  # noqa: E731  the issuer's clock is two minutes ahead of the server's
    assert az.fetch(issuer(az, clock=fast).blob(container, "a.txt").url) == (200, b"AAA")
    assert az.fetch(issuer(az, clock=fast, policy=Policy(skew=timedelta(0))).blob(container, "a.txt").url)[0] == 403, "not yet valid"


@pytest.mark.parametrize("changes", [
    {"sp": "rw"}, {"sp": "racwd"}, {"sr": "c"}, {"se": "2099-01-01T00:00:00Z"}, {"st": "2000-01-01T00:00:00Z"},
    {"spr": None}, {"sip": "198.51.100.7"}, {"sv": "2020-02-10"}, {"sig": "AAAA" + "B" * 40 + "="},
])
def test_changing_any_signed_parameter_breaks_the_signature(az, container, changes):
    t = issuer(az).blob(container, "a.txt")
    assert az.fetch(retarget(t.url, **changes))[0] == 403


def test_an_unmodified_token_still_works_after_all_that(az, container):
    assert az.fetch(issuer(az).blob(container, "a.txt").url) == (200, b"AAA")


def test_a_container_token_lists_and_reads_but_cannot_write(az, container):
    t = issuer(az, policy=Policy(allow_container_scope=True)).container(container, "rl")
    status, body = az.fetch(f"{az.endpoint}/{container}?restype=container&comp=list&{t.query}")
    assert status == 200 and b"a.txt" in body and b"b.txt" in body
    assert az.fetch(f"{url_of(az, container, 'b.txt')}?{t.query}") == (200, b"BBB")
    assert az.fetch(f"{url_of(az, container, 'c.txt')}?{t.query}", "PUT", b"x")[0] == 403


def test_a_token_that_demands_https_is_refused_over_plain_http(az_http, container_http):
    t = issuer(az_http).blob(container_http, "a.txt")
    assert "spr=https" in t.query and az_http.fetch(t.url)[0] == 403


def test_the_same_token_without_the_https_requirement_works_over_http_and_the_audit_flags_it(az_http, container_http):
    weak = generate_blob_sas(account_name=ACCOUNT, container_name=container_http, blob_name="a.txt", account_key=az_http.key,
                             permission=BlobSasPermissions(read=True), expiry=datetime.now(timezone.utc) + 10 * MIN)
    assert az_http.fetch(f"{url_of(az_http, container_http)}?{weak}") == (200, b"AAA")
    assert "SAS-005" in {f.id for f in audit(weak)}


# --- stored access policies: revoking before expiry ------------------------------------------------------------------------

def test_deleting_a_stored_policy_revokes_every_token_that_refers_to_it_at_once(az, container):
    iss, svc = issuer(az), az.service()
    iss.create_stored_policy(svc, container, "readers", "r")
    iss.create_stored_policy(svc, container, "others", "r")
    a, b = iss.blob_via_policy(container, "a.txt", "readers"), iss.blob_via_policy(container, "b.txt", "readers")
    other = iss.blob_via_policy(container, "a.txt", "others")
    assert [az.fetch(t.url)[0] for t in (a, b, other)] == [200, 200, 200]
    iss.revoke(svc, container, "readers")
    assert [az.fetch(t.url)[0] for t in (a, b, other)] == [403, 403, 200], "only the revoked policy's tokens stop"


def test_a_stored_policys_own_expiry_is_enforced(az, container):
    iss, svc = issuer(az), az.service()
    iss.create_stored_policy(svc, container, "short", "r", ttl=timedelta(seconds=3))
    t = iss.blob_via_policy(container, "a.txt", "short")
    assert az.fetch(t.url)[0] == 200
    time.sleep(4)
    assert az.fetch(t.url)[0] == 403


def test_a_token_naming_a_policy_that_does_not_exist_is_refused(az, container):
    iss, svc = issuer(az), az.service()
    iss.create_stored_policy(svc, container, "readers", "r")
    t = iss.blob_via_policy(container, "a.txt", "readers")
    assert az.fetch(retarget(t.url, si="nosuchpolicy"))[0] == 403


def test_policies_are_checked_when_defined_and_the_issuer_will_not_use_one_it_does_not_know(az, container):
    iss, svc = issuer(az), az.service()
    with pytest.raises(PolicyViolation, match="never granted"):
        iss.create_stored_policy(svc, container, "bad", "rd")
    with pytest.raises(PolicyViolation, match="longer than"):
        iss.create_stored_policy(svc, container, "long", "r", ttl=timedelta(hours=5))
    with pytest.raises(PolicyViolation, match="unknown stored policy"):
        iss.blob_via_policy(container, "a.txt", "never-created")


def test_a_stored_policy_that_can_write_is_not_allowed_by_default(az, container):
    with pytest.raises(PolicyViolation, match="not allowed"):
        issuer(az).create_stored_policy(az.service(), container, "w", "cw", ttl=10 * MIN)


# --- what the issuer refuses, and what that refusal prevents ----------------------------------------------------------------

@pytest.mark.parametrize("kw", [
    dict(permissions="rd"), dict(permissions="rwd"), dict(permissions="x"), dict(ttl=timedelta(hours=2)), dict(ttl=timedelta(days=365)),
    dict(permissions="cw"), dict(permissions="rl"), dict(blob="*.txt"), dict(blob=""),
])
def test_the_issuer_refuses_weak_requests(az, container, kw):
    args = dict(container=container, blob="a.txt")
    args.update(kw)
    with pytest.raises(PolicyViolation):
        issuer(az).blob(**args)


def test_what_a_delete_token_would_have_done_and_what_the_audit_says_about_it(az, container):
    weak = generate_blob_sas(account_name=ACCOUNT, container_name=container, blob_name="a.txt", account_key=az.key,
                             permission=BlobSasPermissions(read=True, delete=True), expiry=datetime.now(timezone.utc) + 10 * MIN, protocol="https")
    url = f"{url_of(az, container)}?{weak}"
    assert has_errors(audit(weak)) and "SAS-004" in {f.id for f in audit(weak)}
    assert az.fetch(url, "DELETE")[0] == 202, "the permission is real: this is what the rule keeps out of circulation"
    assert az.fetch(url)[0] == 404


def test_tokens_the_issuer_produces_have_no_audit_errors(az, container):
    iss = issuer(az, policy=Policy(allow_write=True, allow_container_scope=True))
    tokens = [iss.blob(container, "a.txt"), iss.blob(container, "a.txt", ip="203.0.113.1"), iss.blob(container, "x.txt", "cw", ip="203.0.113.1"),
              iss.container(container, "rl")]
    for t in tokens:
        findings = audit(t.url)
        assert not has_errors(findings), [str(f) for f in findings]
        assert "SAS-005" not in {f.id for f in findings}


def test_tokens_via_a_stored_policy_have_no_audit_errors_and_no_revocation_warning(az, container):
    iss, svc = issuer(az), az.service()
    iss.create_stored_policy(svc, container, "readers", "r")
    findings = audit(iss.blob_via_policy(container, "a.txt", "readers").url)
    assert not has_errors(findings) and "SAS-013" not in {f.id for f in findings} and "SAS-008" in {f.id for f in findings}


# --- a limit of the emulator, written down so nobody mistakes it for a guarantee -------------------------------------------------

def test_known_emulator_gap_ip_restrictions_are_not_enforced_by_azurite(az, container):
    t = issuer(az).blob(container, "a.txt", ip="203.0.113.1-203.0.113.9")
    assert "sip=" in t.query
    assert az.fetch(t.url)[0] == 200, (
        "Azurite served a token restricted to 203.0.113.x from 127.0.0.1. If this fails, Azurite now enforces sip: "
        "update this test and the README, which currently say the IP rule is verified only statically.")
    assert "SAS-006" not in {f.id for f in audit(t.url)}
