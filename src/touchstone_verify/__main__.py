"""CLI:  python -m touchstone_verify <disclosure.json | /d/<token> | <token> | URL>

Reads a bundle from a file, a https URL, or a Touchstone disclosure token (fetched
from --base, default https://touchstone.cv), verifies it, and prints PASS/FAIL.
Exit 0 = verified, 1 = failed, 2 = could not load.
"""
import json
import re
import sys
import urllib.request

from .verify import verify_disclosure

GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def _load(arg: str, base: str) -> dict:
    if arg.startswith("http://") or arg.startswith("https://"):
        with urllib.request.urlopen(arg, timeout=15) as r:
            return json.load(r)
    try:
        with open(arg, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, OSError):
        token = arg.rsplit("/", 1)[-1]
        if not re.match(r"^[0-9a-f]{8,64}$", token):
            raise SystemExit(f"not a file, URL, or disclosure token: {arg}")
        with urllib.request.urlopen(f"{base}/d/{token}", timeout=15) as r:
            return json.load(r)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    base = "https://touchstone.cv"
    if "--base" in argv:
        i = argv.index("--base")
        base = argv[i + 1].rstrip("/")
        del argv[i:i + 2]
    if not argv:
        print("usage: python -m touchstone_verify <file|url|token> [--base URL]", file=sys.stderr)
        return 2

    try:
        bundle = _load(argv[0], base)
    except Exception as e:  # noqa: BLE001
        print(f"could not load: {e}", file=sys.stderr)
        return 2

    res = verify_disclosure(bundle)
    if not res.get("format_ok"):
        print(f"{RED}NOT A DISCLOSURE{RST}: {res.get('error')}")
        return 2

    print(f"recorder {res['recorder']}  subject {res.get('subject')}  tier {res.get('tier')}\n")
    for c in res.get("checkpoints", []):
        mark = GREEN + "✓" + RST if c["ok"] else (RED + "✗" + RST)
        print(f"  [{mark}] {c['msg']}")
    for e in res["entries"]:
        print(f"  seq {e['seq']} ({e['type']}){' [redacted]' if e['redacted'] else ''}:")
        for c in e["checks"]:
            mark = GREEN + "✓" + RST if c["ok"] else (RED + "✗" + RST)
            tail = "" if c["fatal"] else f" {DIM}(info){RST}"
            print(f"    [{mark}] {c['msg']}{tail}")

    print("")
    if res["ok"]:
        print(f"{GREEN}PASS{RST} — integrity, attribution and ordering hold (not completeness).")
        return 0
    print(f"{RED}FAIL{RST} — a load-bearing check did not hold.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
