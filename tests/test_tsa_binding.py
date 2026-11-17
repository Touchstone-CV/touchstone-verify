"""The timestamp response must commit to the head it is attached to: the same cases verify.php and verifier.js run.

A disclosure carries, per checkpoint, an RFC 3161 response. Until this check no verifier read it, so a bundle whose
head was changed, with the old response left in place, passed. tests/tsa_binding_cases.json (a copy of the monorepo's
tests/fixtures/tsa_binding_cases.json) names two existing public bundles, copied byte for byte into tests/tsa_binding/,
and eleven vectors that each harness makes from ONE anchor by the edits the file describes. Nothing is signed here.
Dep-free.

Runnable with pytest or as a plain script: python tests/test_tsa_binding.py
"""
import base64
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify import tsa_binding, verify_disclosure  # noqa: E402

HERE = os.path.dirname(__file__)


def _cases():
    with open(os.path.join(HERE, "tsa_binding_cases.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _bundle(bc):
    with open(os.path.join(HERE, bc["file"]), "rb") as fh:
        raw = fh.read()
    assert hashlib.sha256(raw).hexdigest() == bc["sha256"], f"{bc['file']} is not the published file"
    return json.loads(raw.decode("utf-8"))


def _served_anchor(tc):
    served = _bundle(tc["bundles"][0])
    for ci, cp in enumerate(served["checkpoints"]):
        for ai, a in enumerate(cp.get("anchors") or []):
            if a.get("method") == "tsa":
                return served, ci, ai
    raise AssertionError("the bundle as served carries no timestamp anchor")


def test_the_two_public_bundles():
    tc = _cases()
    for bc in tc["bundles"]:
        r = verify_disclosure(_bundle(bc))
        assert r["ok"] is bc["expect_ok"], f"{bc['file']}: ok={r['ok']}, expected {bc['expect_ok']}"
        said = [c for c in r.get("checkpoints", []) if bc["a_checkpoint_line_says"] in c["msg"] and c["ok"] is bc["expect_ok"]]
        assert said, f"{bc['file']}: no checkpoint line says {bc['a_checkpoint_line_says']!r}"


def test_the_vectors():
    tc = _cases()
    served, ci, ai = _served_anchor(tc)
    cp = served["checkpoints"][ci]
    ran = []
    for v in tc["vectors"]:
        blob = json.loads(cp["anchors"][ai]["token_blob"])
        head = cp["head_hash"]
        if v.get("head") == "other":
            head = tc["other_head"]
        elif isinstance(v.get("head"), str) and v["head"].startswith("set:"):
            head = v["head"][4:]
        if v.get("digest") == "other":
            blob["digest"] = tc["other_head"]
        elif v.get("digest") == "absent":
            blob.pop("digest", None)
        if "response" in v:
            der = base64.b64decode(blob["response_b64"])
            e = v["response"]
            if e.startswith("truncate:"):
                blob["response_b64"] = base64.b64encode(der[:int(e[9:])]).decode()
            elif e.startswith("append:"):
                blob["response_b64"] = base64.b64encode(der + bytes.fromhex(e[7:])).decode()
            elif e.startswith("set:"):
                blob["response_b64"] = e[4:]
            elif e == "absent":
                blob.pop("response_b64", None)
            else:
                raise AssertionError("unknown response edit " + e)
        t = tsa_binding(blob, head)
        assert t["state"] == v["expect"], f"vector {v['name']}: {t['state']} ({t['reason']}), expected {v['expect']}"
        assert v["says"] in t["reason"], f"vector {v['name']}: {t['reason']!r} does not say {v['says']!r}"
        ran.append(v["name"])
    assert len(ran) == len(tc["vectors"]) == len(set(ran)) == 11, "all vectors of the cases file run, each once"


def test_the_wiring():
    """The same edits, made inside the bundle as served, must reach verify_disclosure's verdict."""
    tc = _cases()
    served, ci, ai = _served_anchor(tc)

    def wired(change):
        b = copy.deepcopy(served)
        a = b["checkpoints"][ci]["anchors"][ai]
        blob = json.loads(a["token_blob"])
        change(blob)
        a["token_blob"] = json.dumps(blob)
        return b

    cut = verify_disclosure(wired(lambda bl: bl.__setitem__("response_b64", base64.b64encode(base64.b64decode(bl["response_b64"])[:200]).decode())))
    assert cut["ok"] is False, "the bundle as served, response cut, must be rejected"
    bare = verify_disclosure(wired(lambda bl: bl.pop("response_b64")))
    assert bare["ok"] is True, "the bundle as served, response removed, is not rejected"
    assert any("no response is carried" in c["msg"] for c in bare["checkpoints"]), "a line says nothing binds the timestamp"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted((k, v) for k, v in globals().items() if k.startswith("test_") and callable(v)):
        try:
            fn()
            print(f"  ok  {name}")
        except AssertionError as ex:
            failures += 1
            print(f"  FAIL {name}: {ex}")
    print("TSA BINDING " + ("FAILED" if failures else "OK"))
    sys.exit(1 if failures else 0)
