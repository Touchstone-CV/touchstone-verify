"""Regression tests for the 0.4.0 additions — dep-free (run: python tests/test_columns_and_beacon.py):

  1. beacon-bound entry_hash: the fold is appended ONLY when server_beacon is present, so unbound
     entries keep the exact legacy preimage (every pre-existing anchor still verifies).
  2. grade_columns k-model: derivable/witnessed/testimony, distinct-control collapse (the sock-puppet
     defence), over-claim rejection, and set-digest binding.

Witnessed cases run against the shared columns fixture (real signatures), so no crypto-minting
dependency is needed here.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify import find_columns, grade_columns  # noqa: E402
from touchstone_verify.verify import _entry_hash  # noqa: E402

DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FIX = json.load(open(os.path.join(DIR, "columns_valid.json"), encoding="utf-8"))

_checks = []


def check(cond, label):
    _checks.append((bool(cond), label))
    print(f"  {'ok ' if cond else 'FAIL'}  {label}")


# --- 1. beacon-bound entry_hash fold -----------------------------------------------------------
E = {"seq": 7, "prev_hash": "aa", "server_ts": "2026-07-11T00:00:00Z", "payload_hash": "bb",
     "actor_sub": "acct:issuer", "counterparty_sub": None, "actor_sig": "sig=="}


def test_entry_hash():
    legacy = hashlib.sha256("7\naa\n2026-07-11T00:00:00Z\nbb\nacct:issuer\n\nsig==".encode()).hexdigest()
    check(_entry_hash(E) == legacy, "unbound entry_hash == legacy 7-field preimage (no regression)")
    check(_entry_hash({**E, "server_beacon": None}) == legacy, "explicit null beacon == legacy")

    b = {"chain": "drand:quicknet", "round": 30000000, "randomness": "ab" * 32}
    expected = hashlib.sha256(
        ("7\naa\n2026-07-11T00:00:00Z\nbb\nacct:issuer\n\nsig==\n"
         "beacon:drand:quicknet:30000000:" + "ab" * 32).encode()).hexdigest()
    got = _entry_hash({**E, "server_beacon": b})
    check(got == expected, "beacon appends exactly one canonical line")
    check(got != legacy, "a beacon-bound entry_hash differs from its unbound self")


# --- 2. grade_columns k-model ------------------------------------------------------------------
def test_grade_columns():
    cols, digest = find_columns(FIX)
    r = grade_columns(cols, digest)
    by = {c["name"]: c for c in r["columns"]}
    check(r["coherent"], "shared fixture is coherent")
    check(by["digest"]["k"] == 0, "digest -> k=0 DERIVABLE")
    check(by["delivery_ack"]["k"] == 2, "delivery_ack (1 witness) -> k=2")
    check(by["quorum"]["k"] == 3, "quorum (2 independent witnesses) -> k=3")
    check(by["vendor_probes"]["k"] == 2, "vendor_probes (2 keys, 1 controller) collapses -> k=2 not 3")
    check(by["note"]["ok"] is None and by["note"]["k"] == 1, "note -> k=1 TESTIMONY")
    check(r["min_k"] == 1, "min_k = 1 (the testimony is the cheapest falsehood path)")

    # sock-puppet: relabel the collapsed pair k=3 -> OVER-CLAIMED -> incoherent
    sock = json.loads(json.dumps(FIX))
    for c in sock["columns"]:
        if c["name"] == "vendor_probes":
            c["k"] = 3
    sr = grade_columns(sock["columns"])  # (digest would also fail, but the over-claim alone must)
    vp = next(c for c in sr["columns"] if c.get("name") == "vendor_probes")
    check(not sr["coherent"] and vp["status"] == "OVER-CLAIMED", "sock-puppet k=3 over the collapsed pair -> rejected")

    # dep-free fail-closed: testimony declaring k=2 (no witness) over-claims; k=0 without derivation too
    check(not grade_columns([{"name": "t", "k": 2, "proposition": "p", "value": "v"}])["coherent"],
          "testimony declaring k=2 (no witness) -> rejected")
    check(not grade_columns([{"name": "t", "k": 0, "proposition": "p", "value": "v"}])["coherent"],
          "testimony declaring k=0 (no derivation) -> rejected")
    d = {"name": "d", "k": 0, "value": hashlib.sha256(b"abc").hexdigest(),
         "derivation": {"alg": "sha256", "input": "abc"}}
    check(grade_columns([d])["coherent"] and grade_columns([d])["min_k"] is None,
          "pure derivable row -> coherent, min_k None (uncollusible)")

    # set-digest binding: a wrong columns_sha256 makes the whole set incoherent
    check(not grade_columns(cols, "0" * 64)["coherent"], "wrong columns_sha256 -> incoherent")


def main():
    test_entry_hash()
    test_grade_columns()
    print()
    bad = [lbl for ok, lbl in _checks if not ok]
    if bad:
        print("FAILED:")
        for lbl in bad:
            print("  -", lbl)
        return 1
    print("ALL %d CHECKS PASSED — beacon fold backward-compatible; k-model coherent & fail-closed." % len(_checks))
    return 0


if __name__ == "__main__":
    sys.exit(main())
