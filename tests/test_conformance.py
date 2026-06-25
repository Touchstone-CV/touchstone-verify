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
