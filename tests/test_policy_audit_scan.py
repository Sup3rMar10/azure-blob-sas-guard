"""The policy, the audit rules and the repository scanner: no Azure needed."""

import io
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone

import pytest

from sasguard import Policy, RULES, audit, check_request, has_errors, mask, parse_query, scan_paths, scan_text
from sasguard.__main__ import main
from sasguard.audit import NotASas, parse_time

MIN = timedelta(minutes=1)
NOW = datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc)
SIG = "SENTINELSIGNATURE0123456789abcdefABCDEF%2Bxyz%3D"   # a made-up value; the tests assert it is never printed


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def tok(drop=(), **over):
    """A SAS query string. The default is clean except for the warnings every account-key token has."""
    p = {"sv": "2023-11-03", "sr": "b", "sp": "r", "st": iso(NOW - 5 * MIN), "se": iso(NOW + 10 * MIN), "spr": "https", "sip": "203.0.113.1",
         "si": "reader", "sig": SIG}
    p.update(over)
    return "&".join(f"{k}={v}" for k, v in p.items() if k not in drop and v is not None)


def ids(token, **kw):
    return sorted(f.id for f in audit(token, NOW, **kw))


def errors(token, **kw):
    return sorted(f.id for f in audit(token, NOW, **kw) if f.severity == "error")


# --- the issuing policy ---------------------------------------------------------------------------------------------

def req(permissions="r", ttl=10 * MIN, container=False, blob="a.txt", ip=None, **policy):
    return check_request(permissions, ttl, container_scope=container, has_blob=blob is not None, blob=blob, ip=ip, policy=Policy(**policy))


def test_a_short_read_only_blob_token_is_allowed():
    assert req() == []


@pytest.mark.parametrize("kw,fragment", [
    (dict(permissions=""), "no permissions"), (dict(permissions="rr"), "repeat"), (dict(permissions="z"), "unknown"),
    (dict(permissions="rd"), "never granted"), (dict(permissions="x"), "never granted"), (dict(permissions="rt"), "never granted"),
    (dict(permissions="rw", allow_write=False), "not allowed"), (dict(permissions="rl"), "cannot list"),
    (dict(blob=None), "needs a blob name"), (dict(blob=""), "needs a blob name"), (dict(blob="logs/*"), "exact blob"),
    (dict(blob="a?.txt"), "exact blob"), (dict(blob="folder/"), "exact blob"),
    (dict(ttl=timedelta(0)), "positive"), (dict(ttl=-MIN), "positive"), (dict(ttl=61 * MIN), "longer than"),
])
def test_refusals(kw, fragment):
    problems = req(**kw)
    assert problems and any(fragment in p for p in problems), problems


def test_every_reason_is_reported_not_only_the_first():
    assert len(req(permissions="rdz", ttl=-MIN, blob=None)) >= 4


def test_lifetime_limits_are_exact_and_differ_for_reading_and_writing():
    assert req(ttl=60 * MIN) == [] and req(ttl=60 * MIN + timedelta(seconds=1))
    assert req("cw", 15 * MIN, ip="1.2.3.4", allow_write=True) == []
    assert req("cw", 15 * MIN + timedelta(seconds=1), ip="1.2.3.4", allow_write=True)


def test_writing_needs_an_ip_unless_the_policy_waives_it():
    assert any("IP" in p for p in req("w", ip=None, allow_write=True))
    assert req("w", ip="1.2.3.4", allow_write=True) == []
    assert req("w", ip=None, allow_write=True, require_ip_for_write=False) == []


def test_container_scope_is_refused_by_default_and_never_with_write():
    assert any("every blob" in p for p in req("r", container=True, blob=None))
    assert req("rl", container=True, blob=None, allow_container_scope=True) == []
    assert any("must not be able to write" in p for p in req("rw", container=True, blob=None, allow_container_scope=True, allow_write=True, ip="1.2.3.4"))


# --- the audit rules ---------------------------------------------------------------------------------------------------

def test_a_user_delegation_token_with_https_ip_and_a_short_life_has_no_findings():
    t = tok(drop=("si",), skoid="11111111-1111-1111-1111-111111111111", sktid="22222222-2222-2222-2222-222222222222")
    assert audit(t, NOW) == []


def test_an_account_key_token_with_a_stored_policy_has_only_the_key_warning():
    assert [(f.id, f.severity) for f in audit(tok(), NOW)] == [("SAS-007", "warn")]


@pytest.mark.parametrize("token,expected", [
    (tok(drop=("se", "si")), ["SAS-001", "SAS-007", "SAS-013"]),  # no expiry and nothing to revoke it with
    (tok(drop=("se",)), ["SAS-007", "SAS-008"]),
    (tok(se="garbage"), ["SAS-001", "SAS-007"]),
    (tok(sp="rd"), ["SAS-004", "SAS-007"]),
    (tok(sp="rx"), ["SAS-004", "SAS-007"]),
    (tok(spr=None), ["SAS-005", "SAS-007"]),
    (tok(spr="https,http"), ["SAS-005", "SAS-007"]),
    (tok(spr="http"), ["SAS-005", "SAS-007"]),
    (tok(drop=("sip",)), ["SAS-006", "SAS-007"]),
    (tok(drop=("si",)), ["SAS-007", "SAS-013"]),
    (tok(ss="b", srt="co"), ["SAS-007", "SAS-009"]),
    (tok(sr="c"), ["SAS-007", "SAS-011"]),
    (tok(sr="c", sp="rlw"), ["SAS-007", "SAS-010", "SAS-011"]),
    (tok(sp="rw", drop=("sip",)), ["SAS-006", "SAS-007", "SAS-012"]),
    (tok(se=iso(NOW - MIN), st=iso(NOW - 10 * MIN)), ["SAS-003", "SAS-007"]),
])
def test_each_rule_fires_on_its_mistake(token, expected):
    assert ids(token) == expected


@pytest.mark.parametrize("minutes,bad", [(60, False), (65, False), (65.02, True), (120, True), (60 * 24, True), (60 * 24 * 365 * 8, True)])
def test_the_lifetime_limit_allows_for_the_backdated_start_and_no_more(minutes, bad):
    # start is 5 minutes in the past by construction, so a token with `minutes` left is valid for minutes + 5 in total
    t = tok(st=iso(NOW - 5 * MIN), se=iso(NOW + timedelta(minutes=minutes - 5)))
    assert ("SAS-002" in ids(t)) is bad


def test_a_token_with_no_start_is_measured_from_now():
    assert "SAS-002" not in ids(tok(drop=("st",), se=iso(NOW + 60 * MIN)))
    assert "SAS-002" in ids(tok(drop=("st",), se=iso(NOW + 61 * MIN)))


def test_write_tokens_have_the_shorter_limit():
    ok = tok(sp="cw", st=iso(NOW - 5 * MIN), se=iso(NOW + 15 * MIN))
    too_long = tok(sp="cw", st=iso(NOW - 5 * MIN), se=iso(NOW + 16 * MIN))
    assert "SAS-002" not in ids(ok) and "SAS-002" in ids(too_long)


def test_a_date_only_expiry_is_read_as_midnight_utc():
    assert parse_time("2026-10-18") == datetime(2026, 10, 18, tzinfo=timezone.utc)
    assert parse_time("2026-10-18T10:30Z") == datetime(2026, 10, 18, 10, 30, tzinfo=timezone.utc)
    assert parse_time("nonsense") is None
    assert "SAS-002" in ids(tok(se="9999-12-31"))


def test_a_url_and_a_bare_query_audit_the_same():
    url = "https://acct.blob.core.windows.net/data/a.txt?" + tok()
    assert ids(url) == ids(tok()) == ids("?" + tok())


def test_parse_query_lowercases_keys_and_needs_a_signature():
    assert parse_query("SV=2023&SIG=abc")["sig"] == "abc"
    with pytest.raises(NotASas):
        parse_query("sv=2023&sp=r")


def test_severities_split_errors_from_warnings():
    f = audit(tok(spr=None, drop=("sip",)), NOW)
    assert has_errors(f) and {x.id: x.severity for x in f}["SAS-006"] == "warn"
    assert not has_errors(audit(tok(), NOW))


def test_every_rule_in_the_table_is_exercised_by_a_test_above():
    seen = set()
    for t in [tok(drop=("se", "si")), tok(drop=("se",)), tok(sp="rd"), tok(spr=None), tok(drop=("sip",)), tok(drop=("si",)), tok(ss="b"),
              tok(sr="c"), tok(sr="c", sp="rlw"), tok(sp="rw", drop=("sip",)), tok(se=iso(NOW - MIN)), tok(se="9999-12-31")]:
        seen |= set(ids(t))
    assert seen == set(RULES)


# --- the scanner ---------------------------------------------------------------------------------------------------------

URL = "https://myacct.blob.core.windows.net/backups/db.bak?" + tok()


def test_a_sas_url_in_text_is_found_with_its_line_and_the_signature_masked():
    hits = scan_text(f"line one\nexport URL='{URL}'\n", "x.sh", NOW)
    assert len(hits) == 1 and hits[0].line == 2 and hits[0].path == "x.sh"
    assert SIG not in hits[0].masked and "sig=****" in hits[0].masked


def test_a_bare_token_in_a_config_file_is_found_too():
    hits = scan_text(f'sas_token = "{tok()}"\n', "app.ini", NOW)
    assert len(hits) == 1 and SIG not in hits[0].masked


def test_a_url_is_reported_once_not_twice():
    assert len(scan_text(URL, "u", NOW)) == 1


def test_two_tokens_on_one_line_are_two_hits():
    assert len(scan_text(f"{URL} {URL.replace('db.bak', 'other.bak')}", "u", NOW)) == 2


@pytest.mark.parametrize("text", [
    "https://myacct.blob.core.windows.net/backups/db.bak",                 # a plain blob URL
    "https://example.com/?sig=abcdefghijkl",                              # a sig on some other site
    "sv=2023-11-03 is the storage service version",                       # the word, no signature
    "sig=short", "", "# no tokens here\nprint('hello')\n",
])
def test_ordinary_text_is_not_a_hit(text):
    assert scan_text(text, "u", NOW) == []


def test_hits_carry_the_audit_findings():
    hit = scan_text(tok(spr=None), "u", NOW)[0]
    assert "SAS-005" in {f.id for f in hit.findings}


def test_mask_hides_every_signature_and_nothing_else():
    assert mask("a?sv=1&sig=SECRET&se=2") == "a?sv=1&sig=****&se=2" and mask("sig=A&x=1&SIG=B") == "sig=****&x=1&SIG=****"


def test_scan_paths_walks_directories_skips_vcs_and_tolerates_binary_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "deploy.sh").write_text(f"curl '{URL}'\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text(f"{URL}\n", encoding="utf-8")
    (tmp_path / "blob.bin").write_bytes(b"\xff\xfe\x00\x01" * 100)
    (tmp_path / "clean.txt").write_text("nothing here\n", encoding="utf-8")
    hits = scan_paths([str(tmp_path)], NOW)
    assert [h.path.replace("\\", "/").split("/")[-1] for h in hits] == ["deploy.sh"]


def test_scan_a_single_file(tmp_path):
    f = tmp_path / "one.env"
    f.write_text(f"SAS={tok()}\n", encoding="utf-8")
    assert len(scan_paths([str(f)], NOW)) == 1


# --- the command line ---------------------------------------------------------------------------------------------------------

def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(list(argv))
    return code, out.getvalue(), err.getvalue()


def test_audit_command_exit_codes_and_masking():
    code, out, _ = run("audit", tok(spr=None))
    assert code == 1 and "SAS-005" in out and SIG not in out and "sig=****" in out
    assert run("audit", tok(drop=("si",), skoid="x", sktid="y"))[0] == 0   # a clean user delegation token
    assert run("audit", "sv=2023&sp=r")[0] == 2


def test_scan_command_fails_when_a_token_is_committed_and_never_prints_it(tmp_path):
    (tmp_path / "leak.txt").write_text(f"{URL}\n", encoding="utf-8")
    code, out, _ = run("scan", str(tmp_path))
    assert code == 1 and "SAS token found" in out and SIG not in out
    (tmp_path / "leak.txt").write_text("fixed\n", encoding="utf-8")
    assert run("scan", str(tmp_path))[0] == 0


def test_scan_command_exits_2_for_a_path_that_does_not_exist(tmp_path):
    code, _, err = run("scan", str(tmp_path / "nope"))
    assert code == 2 and "no such path" in err
