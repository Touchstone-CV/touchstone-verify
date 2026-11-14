"""The expected server key: the same nine cases verify.php and verifier.js run, on the same bytes.

A disclosure bundle carries the server key its checkpoint signatures verify under, so a pass with
no expected key shows only that the bundle agrees with itself. The shared corpus is exported without
a server key, so no fixture alone exercises a checkpoint signature. tests/server_key_cases.json (a
copy of the monorepo's tests/fixtures/server_key_cases.json) names two keys and gives, for each valid
fixture and each key, the root signature and the self-anchor signature per checkpoint. The PHP and JS
harnesses assert that the signatures they make are exactly those; this verifier has no signer without
an optional dependency, so it applies them. Dep-free.

Runnable with pytest or as a plain script: python tests/test_server_key.py
"""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify import verify_disclosure  # noqa: E402
from touchstone_verify.__main__ import main as cli  # noqa: E402

HERE = os.path.dirname(__file__)


def _load(*parts):
    with open(os.path.join(HERE, *parts), encoding="utf-8") as fh:
        return json.load(fh)


def _signed(bundle, pub, vectors):
    """The bundle with a server layer: the key, and the given signatures on every checkpoint."""
    b = copy.deepcopy(bundle)
    b["server_pubkey"] = pub
    assert len(b["checkpoints"]) == len(vectors) > 0
    for cp, v in zip(b["checkpoints"], vectors):
        assert cp["id"] == v["checkpoint_id"]
        cp["recorder_sig"] = v["recorder_sig"]
        for a in cp["anchors"]:
            if a["method"] == "self" and a["status"] == "confirmed":
                a["token_blob"] = v["self_anchor"]
    return b


def _msgs(res):
    return "\n".join(c["msg"] for c in res["checkpoints"])


def test_expected_server_key():
    sk = _load("server_key_cases.json")
    k1, k2 = sk["pubkeys"]
    assert "+" in k1 or "/" in k1, "key 1 must use a character the URL-safe alphabet writes differently"
    ran = []

    def done(name):
        if name not in ran:
            ran.append(name)

    for case in _load("fixtures", "manifest.json")["cases"]:
        f = case["file"]
        plain = _load("fixtures", f)
        assert plain.get("server_pubkey") is None, f"{f} is exported without a server key"
        signed = _signed(plain, k1, sk["signatures"][f]["key_1"])
        forged = _signed(plain, k2, sk["signatures"][f]["key_2"])

        r = verify_disclosure(signed)
        assert r["ok"] is True and r["server_key"]["state"] == "unconfirmed", f"{f} signed_no_expectation"
        assert "is taken from this bundle" in _msgs(r) and "root signed by the server key in this bundle" in _msgs(r)
        assert "Touchstone server" not in _msgs(r), "no line may call an unconfirmed key Touchstone's"
        assert f'trust tier "{plain["recorder"]["trust_tier"]}" is this bundle\'s own statement' in _msgs(r)
        done("signed_no_expectation")

        r = verify_disclosure(signed, k1)
        assert r["ok"] is True and r["server_key"]["state"] == "expected" and "root signed by the expected server key" in _msgs(r), f"{f} expected_match"
        done("expected_match")

        assert verify_disclosure(signed, k1.replace("+", "-").replace("/", "_"))["ok"] is True, f"{f} expected_urlsafe"
        done("expected_urlsafe")

        r = verify_disclosure(signed, k2)
        assert r["ok"] is False and r["server_key"]["state"] == "mismatch", f"{f} expected_other"
        done("expected_other")

        assert verify_disclosure(forged)["ok"] is True, f"{f} resigned_by_another_key passes with no expected key: the limit"
        assert verify_disclosure(forged, k1)["ok"] is False, f"{f} resigned_by_another_key must be rejected when key 1 is expected"
        done("resigned_by_another_key")

        assert verify_disclosure(plain)["ok"] is True, f"{f} stripped passes with no expected key: the limit"
        r = verify_disclosure(plain, k1)
        assert r["ok"] is False and "this bundle carries none" in _msgs(r), f"{f} stripped must be rejected when a key is expected"
        done("stripped")

        bad = copy.deepcopy(signed)
        bad["checkpoints"][0]["recorder_sig"] = forged["checkpoints"][0]["recorder_sig"]
        assert verify_disclosure(bad)["ok"] is False and verify_disclosure(bad, k1)["ok"] is False, f"{f} bad_root_signature"
        done("bad_root_signature")

        bad = copy.deepcopy(signed)
        bad["checkpoints"][0]["anchors"] = copy.deepcopy(forged["checkpoints"][0]["anchors"])
        assert bad["checkpoints"][0]["anchors"] != signed["checkpoints"][0]["anchors"], f"{f} has a self anchor to forge"
        assert verify_disclosure(bad)["ok"] is False and verify_disclosure(bad, k1)["ok"] is False, f"{f} bad_self_anchor"
        done("bad_self_anchor")

        for malformed in ("", "AAAA", k1.rstrip("="), k1 + "\n", 7):
            assert verify_disclosure(signed, malformed)["ok"] is False, f"{f} malformed_expected {malformed!r}"
        done("malformed_expected")

    assert ran == list(sk["cases"].keys()), "every case the cases file names is run here, and no other"


def test_cli_takes_the_expected_key():
    sk = _load("server_key_cases.json")
    k1, k2 = sk["pubkeys"]
    f = _load("fixtures", "manifest.json")["cases"][0]["file"]
    signed = _signed(_load("fixtures", f), k1, sk["signatures"][f]["key_1"])
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
        json.dump(signed, fh)
        path = fh.name
    try:
        def run(*args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                rc = cli(list(args))
            return rc, out.getvalue()

        rc, text = run(path)
        assert rc == 0 and "was taken from the bundle itself" in text, "with no expected key the pass says what it did not show"
        rc, text = run(path, "--server-key", k1)
        assert rc == 0 and "the server key in this bundle is the expected one" in text and "was taken from the bundle itself" not in text
        rc, text = run("--server-key=" + k2, path)
        assert rc == 1 and "NOT the expected one" in text
        rc, text = run(path, "--server-key=")
        assert rc == 1 and "not a 32-byte Ed25519 key" in text, "an empty value is a malformed key, not an absent one"
        rc, text = run(path, "--server-key")
        assert rc == 2
    finally:
        os.unlink(path)


if __name__ == "__main__":
    test_expected_server_key()
    test_cli_takes_the_expected_key()
    print("server key OK — touchstone-verify runs the shared cases with and without an expected key.")
