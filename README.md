# azure-blob-sas-guard

![ci](https://github.com/Sup3rMar10/azure-blob-sas-guard/actions/workflows/ci.yml/badge.svg)

**Shared access signatures (SAS) for Azure Blob Storage, with a policy that decides whether to sign, an audit that reads tokens, a scanner that finds them in repositories, and tests that check what a real Azurite emulator actually enforces.** A SAS is a bearer credential in a URL: whoever holds it can do what it says until it expires. This repo makes the dangerous choices (delete permission, a day-long lifetime, a container-wide token, no HTTPS requirement) hard to make, and shows the consequences against a running storage emulator.

> **What is verified, and what is not.** 103 tests pass locally on Python 3.13 with Azurite 3.37: 68 need no Azure, and 35 run against real Azurite instances (one serving **HTTPS** with a throwaway certificate, so tokens that demand https can be used; one plain HTTP). I changed the code on purpose eleven times (delete permission allowed, lifetime limit loosened, write without an IP allowed, start not backdated, https dropped from issued tokens, revoke doing nothing, an unknown stored policy accepted, the https audit rule weakened, the skew allowance removed, the signature not masked, and more) and tests failed each time. **No Azure subscription is involved.** Azurite is an emulator: it shows the SDK and the protocol are used correctly, **not** how the real service behaves under load or at its edges. One rule it does **not** enforce is documented below.

## What it does

| Piece | What it does |
|---|---|
| **Policy** (`policy.py`) | What a token may be: read-only by default, never delete (or tags, immutability, move), a blob not a container, one exact blob (no `*`, no folders), at most 1 hour to read and 15 minutes to write, writes only with an IP restriction and only if the policy allows writing. Every reason for a refusal is reported, not just the first. |
| **Issuer** (`issuer.py`) | Signs a token only if the policy allows it. Always `https` only. The start time is **backdated by 5 minutes** so a fast clock somewhere does not make a fresh token "not yet valid". Can create **stored access policies** and issue tokens that refer to them. |
| **Audit** (`audit.py`) | Reads a token or URL: 13 rules (no expiry, too long, expired, forbidden permissions, http allowed, no IP, account-key signed, account-level SAS, container scope, container scope that can write, write without IP, no way to revoke). |
| **Scanner** (`scan.py`) | Finds SAS URLs and bare tokens in files, with the signature **masked in every output** (it must not be the tool that prints a secret into a CI log). The CI job runs it on this repository. |

## What Azurite proves, test by test

| Behaviour (real HTTP requests to Azurite) | Result |
|---|---|
| a read token reads its blob; `PUT` and `DELETE` with it; another blob; listing the container | 200; 403; 403; 403; 403 |
| a write token creates a blob; reading it back with that token; deleting | 201; 403; 403 |
| an expired token | 403 |
| the issuer's clock 2 minutes ahead of the server: backdated start vs zero skew | 200 vs **403 "not yet valid"** |
| changing any signed part of a token (permissions, scope, expiry, start, protocol, IP, version, signature) | 403 each |
| a container token: list and read; write | 200; 403 |
| a token that demands https, used over plain http | 403 |
| the same permissions without the https requirement, over http | 200, and the audit flags it |
| deleting a **stored access policy** revokes every token that refers to it, at once, and only those | 403 for those, 200 for others |
| a stored policy's own expiry | enforced |
| a token with **delete** permission (made directly with the SDK) | really deletes the blob: the reason the rule exists |

## Things I got wrong or hit

- **My tokens could not be tested at all at first.** The issuer always demands https, and Azurite serves plain http by default, so every issued token was refused. The tests now start Azurite with a throwaway certificate (made with `openssl` at run time) and talk HTTPS, plus a separate plain-http instance for the one test that wants to see an https-only token refused.
- **The lifetime audit flagged my own tokens.** Backdating the start by the skew makes a perfectly legal 60-minute token look 65 minutes long. The audit now allows exactly the skew on top of the limit when a start time is present (boundary tests on both sides).
- **"No stored access policy" was the wrong complaint for a user delegation SAS**, which cannot use one; its limits are its short life and its delegation key. The rule now applies only to account-key tokens.
- Starting Azurite through its `.cmd` shim on Windows leaves an orphaned node process; the tests use `node azurite.js` (or the `azurite` command on Linux).

## A limit of the emulator, written down

**Azurite does not enforce IP restrictions.** A token restricted to `203.0.113.1-203.0.113.9` was served from `127.0.0.1`. So the IP rules (`SAS-006`, `SAS-012`, and the policy's "a write token needs an IP") are verified **statically only**: the token carries the `sip` parameter and the audit checks for it, but nothing here shows that Azure refuses a request from outside the range. `test_known_emulator_gap_ip_restrictions_are_not_enforced_by_azurite` pins the current behaviour with a message saying to update the test and this README if a newer Azurite starts enforcing it; CI pins Azurite 3.37.0.

## Honest limits

- **Not Azure.** Everything Azurite does here is an emulation. Real Azure's clock-skew tolerance, caching, throttling and error codes may differ. Test against a real storage account before relying on any of it.
- **Signs with the account key, which is the weaker way.** One key signs every SAS, so a token with no stored access policy can only be revoked by rotating the key (which breaks all of them). A **user delegation SAS** signed through Microsoft Entra ID is preferable (and cannot use stored policies); this repo can *audit* one (recognised by `skoid`) but cannot issue one, because Azurite has no Entra ID to ask for a delegation key. Shared-key access should be turned off on a real account where possible.
- **The audit reads a token, not the account.** It cannot see whether the account allows public access, whether shared-key authorization is enabled, what stored policies exist beyond the token's own, or what the account's network rules are.
- **The scanner is a pattern match.** It finds SAS URLs and `sv=...&sig=...` fragments. A token split across lines, base64-wrapped or stored in a binary file is not found; files over 2 MB and `.git`, `node_modules` and similar directories are skipped. It is not a replacement for GitHub secret scanning or a pre-commit hook.
- A token that has already been exposed is exposed: expiry, revocation or key rotation limits the damage; the scanner only finds it.
- Permission letters and limits are defaults, not recommendations for your workload.

## Run it

```
npm install --global azurite        # or set AZURITE_JS to the path of azurite.js; openssl must be on PATH
python -m pip install -r requirements.txt pytest
python -m pytest                    # starts its own Azurite instances with throwaway keys and certificates

python -m sasguard audit "https://acct.blob.core.windows.net/c/b?sv=2023-11-03&sr=b&sp=rwd&se=2099-01-01&sig=..."   # exit 1, signature masked
python -m sasguard scan .           # exit 1 if any SAS token is committed anywhere under .
```
