"""CLI:  python -m touchstone_verify <disclosure.json | /d/<token> | <token> | URL>

Reads a bundle from a file, a https URL, or a Touchstone disclosure token (fetched
from --base, default https://touchstone.cv), verifies it, and prints PASS/FAIL.
Exit 0 = verified, 1 = failed, 2 = could not load.
"""
import json
import re
import sys
import urllib.request

from .columns import find_columns, grade_columns
from .verify import verify_disclosure

GREEN, RED, DIM, RST = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def _kfmt(k):
    return "k=0" if k == 0 else ("k=?" if k is None else f"k={k}")


def print_columns(doc) -> bool | None:
    """Grade and print a `columns` block found on the document (a /columns receipt, a payload, or a
    document carrying one). Returns True when coherent, False when a load-bearing column fails or
    the set digest does not bind, None when the document carries no columns block.

    A signature says WHO said a thing, never WHETHER it happened: each column is graded by k, the
    number of independent parties who must collude before it can be false, COMPUTED from its
    evidence — k=0 recomputed from a published input, k=1+distinct-control witnesses co-signing the
    proposition, k=1 testimony (shown, never counted as verified). Declaring more strength than the
    evidence earns fails closed."""
    cols, digest = find_columns(doc)
    if cols is None:
        return None
    r = grade_columns(cols, digest)
    print("  columns (graded by k, computed from the evidence — not the declared grade):")
    for c in r["columns"]:
        mark = (GREEN + "✓" + RST) if c["ok"] is True else ((RED + "✗" + RST) if c["ok"] is False else (DIM + "·" + RST))
        name = str(c.get("name") or "?")
        print(f"    [{mark}] {name:<22} {c['status']:<16} {_kfmt(c['k'])}  {DIM}{c.get('note', '')}{RST}")
    if digest is not None:
        dmark = (GREEN + "✓" + RST) if r["digest_ok"] else (RED + "✗" + RST)
        print(f"    [{dmark}] columns_sha256 {'binds the set' if r['digest_ok'] else 'does NOT match sha256(JCS(columns))'}")
    if r["coherent"]:
        cheapest = "no coalition can forge a load-bearing column" if r["min_k"] is None else f"cheapest falsehood path k={r['min_k']}"
        print(f"  {GREEN}COLUMNS COHERENT{RST} — every column carries the strength it claims; {cheapest}.")
    else:
        print(f"  {RED}COLUMNS INCOHERENT{RST} — {r['n_fail']} column(s) fail or the set digest does not bind.")
    return bool(r["coherent"])


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
        # Not a disclosure — but a columns receipt (/columns/<recorder>/<seq>, or any document carrying
        # a `columns` block) is still gradable on its own. The anchor walk is the receipt's `anchor`
        # links; this grades the columns and says so.
        cols_ok = print_columns(bundle)
        if cols_ok is None:
            print(f"{RED}NOT A DISCLOSURE{RST}: {res.get('error')}")
            return 2
        print(f"\n{DIM}(not a disclosure bundle: columns graded; anchoring not checked here — follow the receipt's anchor links){RST}")
        return 0 if cols_ok else 1

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

    # Column readout: a disclosure (or any entry payload it reveals) may carry a `columns` block. The
    # anchor says the bytes were committed; the grade says how many parties must collude for each
    # column to be false. A failed column makes the whole readout FAIL — a receipt is only as strong
    # as its cheapest falsehood path.
    cols_ok = print_columns(bundle)
    if cols_ok is None:
        for e in bundle.get("entries") or []:
            payload = e.get("payload") if isinstance(e, dict) else None
            if isinstance(payload, dict) and find_columns(payload)[0] is not None:
                print(f"  seq {e.get('seq')} payload:")
                c = print_columns(payload)
                cols_ok = c if cols_ok is None else (cols_ok and c)

    print("")
    if res["ok"] and cols_ok is not False:
        print(f"{GREEN}PASS{RST} — integrity, attribution and ordering hold (not completeness)"
              + ("; columns coherent." if cols_ok else "."))
        return 0
    print(f"{RED}FAIL{RST} — " + ("a column fails or the set digest does not bind." if res["ok"] else "a load-bearing check did not hold."))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
