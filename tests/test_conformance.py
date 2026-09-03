"""Conformance: this verifier against the shared Touchstone corpus (same fixtures
verify.php and verifier.js check). Valid bundles pass; every documented tamper fails.
Runnable with pytest or as a plain script: python tests/test_conformance.py
"""
import base64
import copy
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify import verify_disclosure  # noqa: E402

DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load(name):
    with open(os.path.join(DIR, name), encoding="utf-8") as fh:
        return json.load(fh)


def _first_non_genesis(b):
    return next((e for e in b["entries"] if e["seq"] != 0), b["entries"][0])


TAMPERS = {
    "entry_hash": lambda b: _first_non_genesis(b).__setitem__("entry_hash", "f" * 64),
    "actor_sig": lambda b: _first_non_genesis(b).__setitem__("actor_sig", base64.b64encode(bytes([1] * 64)).decode()),
    "checkpoint_root": lambda b: b.get("checkpoints") and b["checkpoints"][0].__setitem__("merkle_root", "a" * 64),
    "sd_revealed_value": lambda b: next(
        (f.__setitem__("v", "__TAMPERED__") for e in b["entries"] if e.get("sd") for f in e.get("sd_revealed", [])[:1]),
        None,
    ),
    "sd_keyset_drop": lambda b: next(
        (e["sd_keyset"]["keys"].pop() for e in b["entries"] if e.get("sd_keyset", {}).get("keys")),
        None,
    ),
    "inject_epoch": lambda b: b["recorder"].setdefault("signing_keys", []).append({"from_seq": 1, "pubkey": "A" * 43 + "="}),
    # beacon-fold tampers (same four as verifier/conformance_check.mjs): entry_hash commits
    # server_beacon, so each must be rejected. Not applicable to a bundle with no bound entry —
    # the no-change guard in test_corpus skips those.
    "beacon_round": lambda b: next((e["server_beacon"].__setitem__("round", e["server_beacon"]["round"] + 1) for e in b["entries"] if e.get("server_beacon")), None),
    "beacon_randomness": lambda b: next((e["server_beacon"].__setitem__("randomness", "0" * 64) for e in b["entries"] if e.get("server_beacon")), None),
    "beacon_drop": lambda b: next((e.pop("server_beacon") for e in b["entries"] if e.get("server_beacon")), None),
    "beacon_inject": lambda b: next((e.__setitem__("server_beacon", {"chain": "drand:quicknet", "round": 1, "randomness": "0" * 64}) for e in b["entries"] if not e.get("server_beacon")), None),
}


def test_corpus():
    manifest = _load("manifest.json")
    for case in manifest["cases"]:
        bundle = _load(case["file"])
        res = verify_disclosure(bundle)
        assert res["ok"] == case["expect_ok"], f"{case['file']} expected ok={case['expect_ok']}"
        if case.get("withheld_absent"):
            assert case["withheld_absent"] not in json.dumps(bundle), f"{case['file']} leaked withheld content"
        for name in manifest["tampers"]:
            t = copy.deepcopy(bundle)
            TAMPERS[name](t)
            if json.dumps(t) == json.dumps(bundle):
                continue
            assert verify_disclosure(t)["ok"] is False, f"{case['file']} tamper '{name}' must be rejected"


if __name__ == "__main__":
    test_corpus()
    print("conformance OK — touchstone-verify matches the corpus on valid + tampered bundles.")
