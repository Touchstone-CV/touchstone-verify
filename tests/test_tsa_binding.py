"""The timestamp response must commit to the head it is attached to, and the head must be the hash of the checkpoint's
last entry: the same cases verify.php and verifier.js run.

A disclosure carries, per checkpoint, an RFC 3161 response. Until this check no verifier read it, so a bundle whose
head was changed, with the old response left in place, passed. tests/tsa_binding_cases.json (a copy of the monorepo's
tests/fixtures/tsa_binding_cases.json) names two existing public bundles, copied byte for byte into tests/tsa_binding/,
vectors and anchor cases that each harness makes from ONE genuine anchor by the edits the file describes, and the
names of the wiring cases written out below. Nothing is built or signed here and no key is used. The last two wiring
cases edit a fixture that was made with test keys. Dep-free.

Runnable with pytest or as a plain script: python tests/test_tsa_binding.py
"""
import base64
import copy
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify import tsa_anchor_binding, tsa_binding, verify_disclosure  # noqa: E402

HERE = os.path.dirname(__file__)


def _edited_response(b64text, edits, was):
    der, first = base64.b64decode(b64text), True
    for ed in (edits if isinstance(edits, list) else [edits]):
        parts = ed.split(":")
        kind = parts[0]
        if kind == "truncate":
            der = der[:int(parts[1])]
        elif kind == "append":
            der = der + bytes.fromhex(parts[1])
        elif kind in ("patch", "splice"):
            p = int(parts[1])
            put = bytes.fromhex(parts[2] if kind == "patch" else parts[3])
            n = len(put) if kind == "patch" else int(parts[2])
            if first and was is not None:
                assert der[p:p + len(was) // 2].hex() == was, f"edit {ed}: the bytes at {p} are not {was}"
            der = der[:p] + put + der[p + n:]
        else:
            raise AssertionError("unknown response edit " + ed)
        first = False
    return base64.b64encode(der).decode()


def run_tsa_cases(cases_file=None, head_fixture_file=None):
    """Returns (failures, summary). failures is a list of (name, why). A file that is not the published one, or an
    edit that does not land where the case says, raises: that is a broken harness, not a result."""
    cases_file = cases_file or os.path.join(HERE, "tsa_binding_cases.json")
    head_fixture_file = head_fixture_file or os.path.join(HERE, "fixtures", "plain_valid.json")
    failures = []

    def need(cond, name, why):
        if not cond:
            failures.append(("tsa-binding:" + name, why))

    with open(cases_file, encoding="utf-8") as fh:
        tc = json.load(fh)
    d = os.path.dirname(cases_file)

    def fatal_fail(c):
        return c["ok"] is False and c["fatal"] is True

    def cp_lines(r):
        return r.get("checkpoints", [])

    def entry_lines(r):
        return [c for e in r.get("entries", []) for c in e["checks"]]

    # The two bundles: the published bytes, the verdict, and a checkpoint line that says why.
    bundles, results = [], []
    for bc in tc["bundles"]:
        with open(os.path.join(d, bc["file"]), "rb") as fh:
            raw = fh.read()
        assert hashlib.sha256(raw).hexdigest() == bc["sha256"], f"{bc['file']} is not the published file (SHA-256 differs)"
        b = json.loads(raw.decode("utf-8"))
        bundles.append(b)
        r = verify_disclosure(b)
        results.append(r)
        tag = "bundle-as-served" if bc["expect_ok"] else "planted-bundle"
        need(r["ok"] is bc["expect_ok"], tag, f"{bc['file']} gave ok={r['ok']}, expected {bc['expect_ok']}")
        need(any(bc["a_checkpoint_line_says"] in c["msg"] and c["ok"] is bc["expect_ok"] for c in cp_lines(r)), tag,
             f"{bc['file']}: no checkpoint line says \"{bc['a_checkpoint_line_says']}\"")
    served = bundles[0]
    ci, ai = next((i, k) for i, c in enumerate(served["checkpoints"]) for k, a in enumerate(c.get("anchors") or []) if a.get("method") == "tsa")
    cp = served["checkpoints"][ci]
    anchor = cp["anchors"][ai]

    # The vectors: edits of that one anchor's token, given to tsa_binding.
    ran = []
    for v in tc["vectors"]:
        blob = json.loads(anchor["token_blob"])
        head = cp["head_hash"]
        h = v.get("head")
        if h == "other":
            head = tc["other_head"]
        elif h == "upper":
            head = head.upper()
        elif h == "newline":
            head = head + "\n"
        elif isinstance(h, str) and h.startswith("set:"):
            head = h[4:]
        elif h is not None:
            raise AssertionError("unknown head edit " + h)
        dg = v.get("digest")
        if dg == "other":
            blob["digest"] = tc["other_head"]
        elif dg == "absent":
            blob.pop("digest", None)
        elif dg is not None:
            raise AssertionError("unknown digest edit " + dg)
        rs = v.get("response")
        if rs == "absent":
            blob.pop("response_b64", None)
        elif isinstance(rs, str) and rs.startswith("set:"):
            blob["response_b64"] = rs[4:]
        elif rs is not None:
            blob["response_b64"] = _edited_response(blob["response_b64"], rs, v.get("was"))
        t = tsa_binding(blob, head)
        need(t["state"] == v["expect"] and v["says"] in t["reason"], "vector:" + v["name"],
             f"gave {t['state']} ({t['reason']}), expected {v['expect']} saying \"{v['says']}\"")
        ran.append(v["name"])
    need(len(ran) == 27 and len(set(ran)) == 27, "vector-count", f"{len(ran)} vectors ran, expected 27, each once")

    # The anchor cases: edits of the anchor's token_blob, given to tsa_anchor_binding (the reading of a token).
    aran = []
    for v in tc["anchor_vectors"]:
        a = copy.deepcopy(anchor)
        tk = v.get("token")
        if tk is None:
            pass
        elif tk == "absent":
            a.pop("token_blob", None)
        elif tk == "wrap_in_list":
            a["token_blob"] = [a["token_blob"]]
        elif tk.startswith("value:"):
            a["token_blob"] = json.loads(tk[6:])
        elif tk.startswith("cut:"):
            a["token_blob"] = a["token_blob"][:int(tk[4:])]
        elif tk.startswith("nest:"):
            n = int(tk[5:])
            a["token_blob"] = '{"x":' + "[" * (n - 1) + "]" * (n - 1) + "}"
        elif tk.startswith("digits:"):
            a["token_blob"] = '{"n":' + "9" * int(tk[7:]) + "}"
        else:
            raise AssertionError("unknown token edit " + tk)
        t = tsa_anchor_binding(a, cp["head_hash"])
        need(t["state"] == v["expect"] and v["says"] in t["reason"], "anchor:" + v["name"],
             f"gave {t['state']} ({t['reason']}), expected {v['expect']} saying \"{v['says']}\"")
        aran.append(v["name"])
    need(len(aran) == 23 and len(set(aran)) == 23, "anchor-count", f"{len(aran)} anchor cases ran, expected 23, each once")

    # The wiring: the result must reach the verdict and the lines. Names as the cases file lists them.
    wran = []

    def wiring(name, cond, why):
        if name not in wran:
            wran.append(name)
        need(cond, "wiring:" + name, why)

    def with_token(b, change):
        b = copy.deepcopy(b)
        a = next(x for x in b["checkpoints"][ci]["anchors"] if x.get("method") == "tsa")
        blob = json.loads(a["token_blob"])
        change(blob)
        a["token_blob"] = json.dumps(blob, separators=(",", ":"))
        return b

    def cut_response(bl):
        bl["response_b64"] = base64.b64encode(base64.b64decode(bl["response_b64"])[:200]).decode()

    def no_response(bl):
        bl.pop("response_b64", None)

    cut = verify_disclosure(with_token(served, cut_response))
    wiring("response_cut", cut["ok"] is False, "the bundle as served with its response cut was accepted")

    bare = verify_disclosure(with_token(served, no_response))
    wiring("response_removed", bare["ok"] is True and any("no response is carried" in c["msg"] for c in cp_lines(bare)),
           "the bundle as served without a response must pass and say that nothing binds the timestamp")
    wiring("response_removed", not any("response commits to this head" in c["msg"] for c in entry_lines(bare)),
           "a timestamp with no response was still reported as bound")

    junk_b = copy.deepcopy(served)
    next(x for x in junk_b["checkpoints"][ci]["anchors"] if x.get("method") == "tsa")["token_blob"] = "not json"
    junk = verify_disclosure(junk_b)
    wiring("token_unreadable", junk["ok"] is False and any(fatal_fail(c) and "token is unreadable" in c["msg"] for c in cp_lines(junk)),
           "an anchor whose token cannot be read was not rejected with a line that says so")

    wiring("entry_reports_the_failure", any(fatal_fail(c) and "does not bind checkpoint" in c["msg"] for c in entry_lines(results[1])),
           "the planted bundle: no entry line reports the failure as a failure")

    def only_tsa(b):
        b = copy.deepcopy(b)
        b["checkpoints"][ci]["anchors"] = [x for x in b["checkpoints"][ci]["anchors"] if x.get("method") == "tsa"]
        return b

    lone = verify_disclosure(only_tsa(served))
    lone_bare = verify_disclosure(with_token(only_tsa(served), no_response))
    wiring("unbound_is_not_an_anchor", lone["ok"] is True and not any("no confirmed external anchor yet" in c["msg"] for c in entry_lines(lone)),
           "control: with its response, the timestamp alone must count as an anchor")
    wiring("unbound_is_not_an_anchor",
           lone_bare["ok"] is True and all(any("no confirmed external anchor yet" in c["msg"] for c in e["checks"]) for e in lone_bare.get("entries", []))
           and any("not counted as an anchor" in c["msg"] for c in entry_lines(lone_bare)),
           "a timestamp with no response, alone on its checkpoint, was counted as an anchor")

    # An anchors field that is not a list is not read, by any of the three (a PHP array would otherwise walk an object's values).
    odd_b = with_token(served, cut_response)
    odd_b["checkpoints"][ci]["anchors"] = {"only": next(x for x in odd_b["checkpoints"][ci]["anchors"] if x.get("method") == "tsa")}
    odd = verify_disclosure(odd_b)
    wiring("anchors_not_a_list_are_not_read", odd["ok"] is True and not any("does not bind checkpoint" in c["msg"] for c in cp_lines(odd) + entry_lines(odd)),
           "an anchors field that is an object was read: its failing timestamp anchor reached the verdict")

    # The head and its last entry, on a fixture made with test keys.
    with open(head_fixture_file, encoding="utf-8") as fh:
        fx = json.load(fh)
    fcp = fx["checkpoints"][0]
    whole = verify_disclosure(fx)
    swapped = copy.deepcopy(fx)
    swapped["checkpoints"][0]["head_hash"] = tc["other_head"]
    sw = verify_disclosure(swapped)
    head_line = "head is the hash of the entry it ends at"
    wiring("head_is_not_the_last_entry_hash", whole["ok"] is True and any(c["ok"] is True and head_line in c["msg"] for c in cp_lines(whole)),
           "control: the fixture as made must pass and say its head is the hash of its last entry")
    wiring("head_is_not_the_last_entry_hash", sw["ok"] is False and any(fatal_fail(c) and head_line in c["msg"] for c in cp_lines(sw)),
           "a head that is not the hash of the last entry was accepted")
    short = copy.deepcopy(fx)
    short["entries"] = [e for e in short["entries"] if e["seq"] != fcp["seq_end"]]
    sh = verify_disclosure(short)
    wiring("last_entry_not_disclosed",
           len(short["entries"]) == len(fx["entries"]) - 1 and sh["ok"] is True and any("nothing here ties the head to an entry" in c["msg"] for c in cp_lines(sh)),
           "without the last entry the bundle must pass and say that nothing ties the head to an entry")

    # A heartbeat adds no entry: it ends where the checkpoint before it ended and repeats that head. It must not be rejected.
    beat = copy.deepcopy(fx)
    beat["checkpoints"].append({**copy.deepcopy(fcp), "id": fcp["id"] + 1, "seq_start": fcp["seq_end"] + 1, "seq_end": fcp["seq_end"],
                                "prev_checkpoint_hash": fcp["head_hash"], "anchors": [], "witnesses": []})
    hb = verify_disclosure(beat)
    wiring("heartbeat_repeats_the_head", hb["ok"] is True and sum(1 for c in cp_lines(hb) if c["ok"] is True and head_line in c["msg"]) == 2,
           "a heartbeat checkpoint, which repeats the head of the one before it, must pass the head check")

    # The end of a checkpoint, which nobody signs. Only the last leaf of the tree has a proof with no sibling on the right.
    def fails(r, text):
        return r["ok"] is False and any(fatal_fail(c) and text in c["msg"] for c in entry_lines(r))

    late = copy.deepcopy(fx)
    late["checkpoints"][0]["seq_start"] = fcp["seq_start"] + 1
    wiring("an_entry_outside_the_stated_range", fails(verify_disclosure(late), "is outside checkpoint"),
           "an entry proven under a checkpoint whose stated range does not hold its seq was accepted")
    before = next(e for e in fx["entries"] if e["seq"] == fcp["seq_end"] - 1)
    early = copy.deepcopy(fx)
    early["checkpoints"][0]["head_hash"] = before["entry_hash"]
    early["checkpoints"][0]["seq_end"] = before["seq"]
    early_short = copy.deepcopy(early)
    early_short["entries"] = [e for e in early_short["entries"] if e["seq"] != fcp["seq_end"]]
    wiring("end_pointed_at_an_earlier_entry", fails(verify_disclosure(early), "is outside checkpoint"),
           "the end moved to an earlier entry, with the real last entry still in the bundle, was accepted")
    wiring("end_pointed_at_an_earlier_entry", fails(verify_disclosure(early_short), "shows a later leaf"),
           "the end moved to an earlier entry, with the real last entry left out, was accepted")
    far = copy.deepcopy(fx)
    far["checkpoints"][0]["seq_end"] = fcp["seq_end"] + 97
    wiring("end_pointed_past_the_last_entry", fails(verify_disclosure(far), "is the last leaf under checkpoint"), "an end moved past the last entry was accepted")

    # A checkpoint with a malformed id is rejected even when a valid one with the same text form follows it.
    one = copy.deepcopy(fx)
    one["checkpoints"][0]["id"] = 1
    for e in one["entries"]:
        if e.get("checkpoint_id") == fcp["id"]:
            e["checkpoint_id"] = 1
    wiring("a_malformed_id_cannot_hide_behind_a_valid_one", verify_disclosure(one)["ok"] is True, "control: the fixture with its checkpoint numbered 1 must pass")
    for bad in ([1], "1", True):
        b = copy.deepcopy(one)
        b["checkpoints"].insert(0, {**copy.deepcopy(one["checkpoints"][0]), "id": bad})
        r = verify_disclosure(b)
        wiring("a_malformed_id_cannot_hide_behind_a_valid_one", r["ok"] is False and any(fatal_fail(c) and "malformed checkpoint" in c["msg"] for c in cp_lines(r)),
               f"a checkpoint whose id is {json.dumps(bad)}, followed by a valid checkpoint 1, was accepted")

    # A checkpoint that no entry cites (a heartbeat), carrying the served bundle's genuine timestamp anchor, which is for
    # another head: only the checkpoint's own line can fail the bundle. The same heartbeat without an anchor passes (above).
    beat_bad = copy.deepcopy(beat)
    beat_bad["checkpoints"][-1]["anchors"] = [copy.deepcopy(anchor)]
    bb = verify_disclosure(beat_bad)
    wiring("checkpoint_fails_alone",
           bb["ok"] is False and any(fatal_fail(c) and "does not bind checkpoint" in c["msg"] for c in cp_lines(bb))
           and not any("does not bind checkpoint" in c["msg"] for c in entry_lines(bb)),
           "a timestamp that does not bind, on a checkpoint no entry cites, was accepted (or an entry line had to report it)")

    # The entry a checkpoint ends at counts only when its own proof puts it last under the checkpoint's root.
    not_last = "is not shown to be the last leaf under its root"

    def cp_fails(r, text):
        return r["ok"] is False and any(fatal_fail(c) and text in c["msg"] for c in cp_lines(r))

    uncited = copy.deepcopy(fx)
    for e in uncited["entries"]:
        if e["seq"] == fcp["seq_end"]:
            e.pop("checkpoint_id", None)
            e.pop("merkle_proof", None)
    wiring("the_end_entry_must_be_proven_under_the_root", cp_fails(verify_disclosure(uncited), not_last),
           "an end entry that carries no proof was taken as the checkpoint's last leaf")
    unfolding = copy.deepcopy(fx)
    for e in unfolding["entries"]:
        if e["seq"] == fcp["seq_end"]:
            e.pop("checkpoint_id", None)
            e["merkle_proof"] = []
    wiring("the_end_entry_must_be_proven_under_the_root", cp_fails(verify_disclosure(unfolding), not_last),
           "an end entry whose proof does not fold to the checkpoint's root was taken as its last leaf")
    early_loose = copy.deepcopy(early_short)
    for e in early_loose["entries"]:
        if e["seq"] == before["seq"]:
            e.pop("checkpoint_id", None)
    wiring("end_pointed_at_an_earlier_entry", cp_fails(verify_disclosure(early_loose), not_last),
           "an end entry proven under the root, but not as its last leaf, was taken as the checkpoint's last leaf")

    need(sorted(wran) == sorted(tc["wiring"]), "wiring-names", f"ran {wran}, the cases file lists {tc['wiring']}")
    return failures, f"2 bundles, {len(ran)} vectors, {len(aran)} anchor cases, {len(wran)} wiring cases"


def test_timestamp_cases():
    failures, summary = run_tsa_cases()
    assert failures == [], "timestamp cases: " + "; ".join(f"{n}: {w}" for n, w in failures)
    assert summary == "2 bundles, 27 vectors, 23 anchor cases, 15 wiring cases", summary


if __name__ == "__main__":
    fails, summ = run_tsa_cases()
    if fails:
        print("SOUNDNESS REGRESSION — timestamp binding in touchstone_verify:")
        for name, why in fails:
            print(f"  x {name}  {why}")
        raise SystemExit(1)
    print(f"TSA BINDING OK — {summ}")
