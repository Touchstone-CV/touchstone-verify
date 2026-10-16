"""The CLI prints a per-column readout (run: python tests/test_cli_columns.py), dep-free.

The library has graded columns since 0.4.0, but `python -m touchstone_verify <receipt>` never showed
it: a /columns receipt was rejected as NOT A DISCLOSURE and a disclosure whose payload carried columns
printed PASS with the columns ungraded. Now a columns receipt grades on its own (exit 0 coherent, 1 not),
and a disclosure's columns join its verdict (a failed column fails the readout).
"""
import copy
import hashlib
import io
import json
import os
import sys
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify.__main__ import main, print_columns  # noqa: E402

DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FIX = json.load(open(os.path.join(DIR, "columns_valid.json"), encoding="utf-8"))

_checks = []


def check(cond, label):
    _checks.append((bool(cond), label))
    print(f"  {'ok ' if cond else 'FAIL'}  {label}")


def run(doc):
    path = os.path.join(DIR, "_tmp_cli_columns.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            rc = main([path])
    finally:
        os.remove(path)
    return rc, buf.getvalue()


# 1. a bare columns receipt is graded, not rejected
rc, out = run(FIX)
check(rc == 0, "a coherent columns receipt exits 0")
check("COLUMNS COHERENT" in out and "NOT A DISCLOSURE" not in out, "…and prints the coherent readout instead of NOT A DISCLOSURE")
check(out.count("DERIVABLE") >= 1 and out.count("WITNESSED") >= 1 and out.count("TESTIMONY") >= 1, "all three tiers appear in the readout")
check("columns_sha256 binds the set" in out, "the set digest is reported as binding")

# 2. tampering a derivable value fails the readout and the exit code
bad = copy.deepcopy(FIX)
col = next(c for c in bad["columns"] if c.get("derivation"))
col["value"] = "0" * 64
rc2, out2 = run(bad)
check(rc2 == 1 and "COLUMNS INCOHERENT" in out2 and "RECOMPUTE-FAILS" in out2, "a derivable column that does not recompute fails the readout (exit 1)")

# 3. a mutated testimony column breaks the set digest (the digest catches what grading cannot)
bad2 = copy.deepcopy(FIX)
tcol = next(c for c in bad2["columns"] if not c.get("derivation") and not (c.get("witnesses") or c.get("witness")))
tcol["value"] = str(tcol.get("value")) + " (edited)"
rc3, out3 = run(bad2)
check(rc3 == 1 and "does NOT match" in out3, "editing a testimony column breaks columns_sha256 and fails the readout")

# 4. a document with no columns block is still NOT A DISCLOSURE (exit 2), unchanged behaviour
rc4, out4 = run({"hello": "world"})
check(rc4 == 2 and "NOT A DISCLOSURE" in out4, "a document with neither disclosure nor columns is rejected as before")

# 5. print_columns returns None/True/False as documented
check(print_columns({"x": 1}) is None, "print_columns → None without a columns block")
buf = io.StringIO()
with redirect_stdout(buf):
    ok = print_columns(FIX)
check(ok is True, "print_columns → True on the coherent fixture")

failed = [l for ok_, l in _checks if not ok_]
print(f"\n{len(_checks) - len(failed)}/{len(_checks)} checks passed")
sys.exit(1 if failed else 0)
