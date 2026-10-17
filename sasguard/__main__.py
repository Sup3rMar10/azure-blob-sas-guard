"""python -m sasguard audit TOKEN_OR_URL | python -m sasguard scan PATH...

audit: exit 1 if the token has an error finding, 2 if it is not a SAS at all.
scan:  exit 1 if any SAS token is found in the given files (it is a credential in a repository), 2 if a path cannot be read.
Signatures are always masked in the output.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .audit import NotASas, audit, has_errors, parse_query
from .scan import mask, scan_paths


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sasguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("token")
    s = sub.add_parser("scan")
    s.add_argument("paths", nargs="+")
    args = ap.parse_args(argv)
    if args.cmd == "audit":
        try:
            findings = audit(args.token)
        except NotASas as e:
            print(f"not a SAS: {e}", file=sys.stderr)
            return 2
        params = parse_query(args.token)
        print("token:", mask(args.token) if "sig" in params else "(unreadable)")
        for f in findings:
            print(f"  {f}")
        print(f"{sum(f.severity == 'error' for f in findings)} error(s), {sum(f.severity == 'warn' for f in findings)} warning(s)")
        return 1 if has_errors(findings) else 0
    missing = [p for p in args.paths if not Path(p).exists()]
    if missing:
        print(f"cannot scan: no such path: {', '.join(missing)}", file=sys.stderr)
        return 2
    hits = scan_paths(args.paths)
    for h in hits:
        print(f"{h.path}:{h.line}: SAS token found: {h.masked}")
        for f in h.findings:
            if f.severity == "error":
                print(f"    {f}")
    print(f"{len(hits)} SAS token(s) found")
    return 1 if hits else 0


if __name__ == "__main__":
    raise SystemExit(main())
