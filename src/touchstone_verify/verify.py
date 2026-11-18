"""Verify a Touchstone disclosure bundle — independently, with zero dependencies.

A faithful port of verifier/verify.php and public/verifier.js: same JCS, entry_hash,
signed_content, Merkle, selective-disclosure and anchor rules, so all three agree on
the same bytes (checked against the shared conformance corpus). Checks integrity,
attribution (subject signature, epoch-aware for key rotation), ordering, checkpoint
append-only + server signatures + witnesses, selective-disclosure field proofs, and
reports the external anchors. Proves tampering by anyone who is not Touchstone; it
does not prove completeness, and says so.
"""
import hashlib
import json

from ._ed25519 import verify as _ed_verify


def jcs(v) -> str:
    """RFC 8785-ish canonical JSON, matching Canonicalizer.php + verifier.js (no
    non-ASCII escaping, compact separators, recursive key sort)."""
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(v[k]) for k in sorted(v)) + "}"
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _ed(pub_b64: str, msg: str, sig_b64: str) -> bool:
    try:
        pub = _b64(pub_b64)
        sig = _b64(sig_b64)
    except Exception:
        return False
    return _ed_verify(pub, msg.encode("utf-8"), sig)


def _b64(s: str) -> bytes:
    import base64
    return base64.b64decode(s.replace("-", "+").replace("_", "/") + "===")


def _unhex(h) -> bytes:
    # bytes.fromhex skips spaces, so "ab cd" and "abcd" were one hash here and two to verify.php and
    # verifier.js, which refuse anything but hex digits. Refuse it here as well.
    if not isinstance(h, str) or len(h) % 2 or any(c not in "0123456789abcdefABCDEF" for c in h):
        raise ValueError("not hex")
    return bytes.fromhex(h)


def _mleaf(hex_h: str) -> str:
    return _sha256_hex(b"\x00" + _unhex(hex_h))


def _mnode(l: str, r: str) -> str:
    return _sha256_hex(b"\x01" + _unhex(l) + _unhex(r))


def _merkle_from_proof(leaf_hex: str, proof):
    # fail-closed: malformed hash/proof (bad hex, non-list) → None, which equals no root.
    try:
        cur = _mleaf(leaf_hex)
        for step in proof:
            cur = _mnode(cur, step["hash"]) if step.get("side") == "right" else _mnode(step["hash"], cur)
        return cur
    except Exception:
        return None


def _entry_hash(e) -> str:
    parts = [
        str(e["seq"]), e["prev_hash"], e["server_ts"], e["payload_hash"],
        e["actor_sub"], e.get("counterparty_sub") or "", e["actor_sig"],
    ]
    # Beacon-bound entries (recorders with beacon_binding on) commit a drand round into entry_hash as
    # a final `beacon:<chain>:<round>:<randomness>` line, so server_ts carries a checkable not-before.
    # Present ONLY on bound entries → absent yields the exact legacy 7-field preimage, so unbound
    # entries and every pre-existing anchor verify unchanged.
    b = e.get("server_beacon")
    if b is not None:
        if not isinstance(b, dict) or not all(k in b for k in ("chain", "round", "randomness")):
            return "malformed-server_beacon"   # present-but-malformed → never matches → reject (php/js parity)
        parts.append("beacon:%s:%s:%s" % (b["chain"], b["round"], b["randomness"]))
    return _sha256_hex("\n".join(parts).encode("utf-8"))


def _signed_content(recorder_id: str, e) -> str:
    return jcs({
        "v": 1, "recorder_id": recorder_id, "event_type": e["event_type"],
        "actor_sub": e["actor_sub"], "counterparty_sub": e.get("counterparty_sub"),
        "payload_hash": e["payload_hash"], "client_ts": e.get("client_ts"),
    })


def _key32(x):
    """A 32-byte Ed25519 key written as 43 base64 characters and one '=', or None. One shape only,
    checked before decoding, so that this verifier, verify.php and verifier.js cannot differ on a key
    written with whitespace, without padding, or in the other base64 alphabet."""
    import re
    if not isinstance(x, str) or re.fullmatch(r"[A-Za-z0-9+/_-]{43}=", x) is None:
        return None
    try:
        d = _b64(x)
    except Exception:
        return None
    return d if len(d) == 32 else None


# ── RFC 3161: what the carried timestamp response commits to ─────────────────────────────
# A disclosure carries, per checkpoint, the timestamp authority's response. Its TSTInfo holds a
# message imprint: the value the authority stamped. Until this check no verifier read it, so a
# bundle whose head was changed, with the old response left in place, still passed. This is the
# same fixed walk as verify.php and verifier.js (TimeStampResp → timeStampToken → SignedData →
# encapContentInfo → TSTInfo → messageImprint), definite lengths only. It READS the imprint. It
# checks no signature and no certificate: that the authority really signed the response stays
# the reader's job (openssl ts -verify … -CAfile). tests/tsa_binding_cases.json holds the cases
# the three verifiers must agree on.
def _der_tlv(b: bytes, pos: int, end: int):
    if pos + 2 > end:
        return None
    tag, ln, p = b[pos], b[pos + 1], pos + 2
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or p + n > end:      # no indefinite length, nothing absurd
            return None
        ln = int.from_bytes(b[p:p + n], "big")
        p += n
    if p + ln > end:
        return None
    return (tag, p, p + ln)


def _der_children(b: bytes, node):
    out, p = [], node[1]
    while p < node[2]:
        c = _der_tlv(b, p, node[2])
        if c is None:
            return None
        out.append(c)
        p = c[2]
    return out


def tsa_imprint(der: bytes):
    """{status, algorithm_oid_hex, hashed_hex} read from a DER TimeStampResp, or None when it cannot be read."""
    if not isinstance(der, (bytes, bytearray)):
        return None
    der = bytes(der)
    hx = lambda n: der[n[1]:n[2]].hex()  # noqa: E731
    resp = _der_tlv(der, 0, len(der))
    if resp is None or resp[0] != 0x30 or resp[2] != len(der):          # one SEQUENCE, nothing after it
        return None
    r = _der_children(der, resp)
    if r is None or len(r) != 2 or r[0][0] != 0x30 or r[1][0] != 0x30:  # status, timeStampToken
        return None
    st = _der_children(der, r[0])
    if st is None or len(st) < 1 or st[0][0] != 0x02 or st[0][2] - st[0][1] != 1:   # PKIStatus: one INTEGER byte
        return None
    ci = _der_children(der, r[1])
    if ci is None or len(ci) != 2 or ci[0][0] != 0x06 or hx(ci[0]) != "2a864886f70d010702" or ci[1][0] != 0xA0:
        return None
    c0 = _der_children(der, ci[1])
    if c0 is None or len(c0) != 1 or c0[0][0] != 0x30:
        return None
    sd = _der_children(der, c0[0])
    if sd is None or len(sd) < 3 or sd[0][0] != 0x02 or sd[1][0] != 0x31 or sd[2][0] != 0x30:
        return None
    enc = _der_children(der, sd[2])
    if enc is None or len(enc) != 2 or enc[0][0] != 0x06 or hx(enc[0]) != "2a864886f70d0109100104" or enc[1][0] != 0xA0:
        return None
    e0 = _der_children(der, enc[1])
    if e0 is None or len(e0) != 1 or e0[0][0] != 0x04:
        return None
    tst = _der_tlv(der, e0[0][1], e0[0][2])
    if tst is None or tst[0] != 0x30 or tst[2] != e0[0][2]:
        return None
    ti = _der_children(der, tst)
    if ti is None or len(ti) < 3 or ti[0][0] != 0x02 or ti[1][0] != 0x06 or ti[2][0] != 0x30:
        return None
    mi = _der_children(der, ti[2])
    if mi is None or len(mi) != 2 or mi[0][0] != 0x30 or mi[1][0] != 0x04:
        return None
    alg = _der_children(der, mi[0])
    if alg is None or len(alg) < 1 or alg[0][0] != 0x06:
        return None
    return {"status": der[st[0][1]], "algorithm_oid_hex": hx(alg[0]), "hashed_hex": hx(mi[1])}


def tsa_binding(blob, head_hash) -> dict:
    """Does the anchor's carried response commit to this head? state is 'bound' (its message imprint
    is this head), 'fail' (it is carried and is not, or cannot be read, or the digest field
    disagrees), or 'unbound' (no response is carried, so there is nothing to read)."""
    import base64
    import re
    if not isinstance(blob, dict):
        blob = {}
    head = head_hash.lower() if isinstance(head_hash, str) else ""
    if not re.fullmatch(r"[0-9a-f]{64}", head):
        return {"state": "fail", "reason": "the checkpoint head is not a SHA-256 hex string"}
    dg = blob.get("digest")
    if dg is not None and (not isinstance(dg, str) or dg.lower() != head):
        return {"state": "fail", "reason": "the anchor's digest field differs from the checkpoint head"}
    r = blob.get("response_b64")
    if r is None or r == "":
        return {"state": "unbound", "reason": "no timestamp response is carried"}
    if not isinstance(r, str) or len(r) % 4 != 0 or not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", r):
        return {"state": "fail", "reason": "the timestamp response is unreadable (not base64)"}
    try:
        der = base64.b64decode(r, validate=True)
    except Exception:
        return {"state": "fail", "reason": "the timestamp response is unreadable (not base64)"}
    imp = tsa_imprint(der)
    if imp is None:
        return {"state": "fail", "reason": "the timestamp response is unreadable (no message imprint found)"}
    if imp["status"] > 1:
        return {"state": "fail", "reason": f"the timestamp response's status is not granted (status {imp['status']})"}
    if imp["algorithm_oid_hex"] != "608648016503040201":
        return {"state": "fail", "reason": "the response's message imprint is not a SHA-256 imprint"}
    if imp["hashed_hex"] != head:
        return {"state": "fail", "reason": f"the response's message imprint is for another value ({imp['hashed_hex'][:16]}…), not this head"}
    return {"state": "bound", "reason": "the response's message imprint equals this head", "algorithm_oid_hex": imp["algorithm_oid_hex"]}


def tsa_anchor_binding(anchor, head_hash) -> dict:
    """One tsa anchor of a checkpoint: read its token, then ask tsa_binding. The token is a JSON object
    in a string. Absent or empty: nothing is carried. Present and anything else: a failure. The three
    verifiers read it by the same rule (a string, at most 64 opening brackets, no escaped surrogate,
    an object at the top, no NaN or Infinity), so that no JSON dialect decides a verdict."""
    import re
    t = anchor.get("token_blob") if isinstance(anchor, dict) else None
    blob = {}
    if not (t is None or (isinstance(t, str) and t == "")):
        bad = {"state": "fail", "reason": "the anchor's token is unreadable (not a JSON object in a string)", "host": "TSA"}
        if not isinstance(t, str) or t.count("[") + t.count("{") > 64 or re.search(r"\\u[dD][89a-fA-F]", t):
            return bad

        def _refuse(_name):
            raise ValueError("NaN and Infinity are not JSON")
        try:   # numbers are never read from a token, so they are not converted: no size limit can decide the parse
            blob = json.loads(t, parse_constant=_refuse, parse_int=lambda _s: 0, parse_float=lambda _s: 0.0)
        except Exception:
            return bad
        if not isinstance(blob, dict):
            return bad
    out = tsa_binding(blob, head_hash)
    out["host"] = _tsa_host(blob)
    return out


def _tsa_host(blob) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(blob.get("tsa")).hostname or "TSA"
    except Exception:
        return "TSA"


def verify_disclosure(b: dict, expected_server_pubkey=None) -> dict:
    """Verify a decoded touchstone-disclosure/1 bundle. Returns
    {ok, format_ok, recorder, subject, tier, entries:[{seq,type,checks:[{ok,fatal,msg}]}],
    checkpoints:[{ok,fatal,msg}]}. `ok` is the AND of all fatal checks."""
    if not isinstance(b, dict) or b.get("format") != "touchstone-disclosure/1":
        return {"ok": False, "format_ok": False, "error": "not a touchstone-disclosure/1 bundle"}

    # structural guard: a malformed top-level shape rejects gracefully (never crashes).
    rec = b.get("recorder")
    entries = b.get("entries")
    _cps = b.get("checkpoints")  # optional; a non-list (null, {}, …) means "none" (matches verify.php/js)
    checkpoints = _cps if isinstance(_cps, list) else []
    # a disclosure must carry a recorder object and a non-empty entries list (genesis at least).
    if not isinstance(rec, dict) or not isinstance(entries, list) or not entries \
            or not all(isinstance(e, dict) for e in entries) or not all(isinstance(c, dict) for c in checkpoints):
        return {"ok": False, "format_ok": False, "error": "malformed bundle structure"}
    _pid = rec.get("public_id")
    recorder_id = _pid if isinstance(_pid, str) else ""
    _pk = rec.get("signing_pubkey")
    pubkey = _pk if isinstance(_pk, str) else ""
    # only well-formed epochs participate; a malformed one is dropped (its rotated key is then
    # untrusted → fail-closed), matching verify.php / verifier.js.
    sk = rec.get("signing_keys")
    epochs = [k for k in sk if isinstance(k, dict) and isinstance(k.get("from_seq"), int)
              and not isinstance(k.get("from_seq"), bool) and isinstance(k.get("pubkey"), str)] if isinstance(sk, list) else []
    epochs = sorted(epochs, key=lambda x: x["from_seq"])

    def key_for_seq(seq: int) -> str:
        k = pubkey
        for ep in epochs:
            if int(ep["from_seq"]) <= seq:
                k = ep["pubkey"]
            else:
                break
        return k

    server_pub = b.get("server_pubkey")
    server_pub = server_pub if isinstance(server_pub, str) and server_pub else None
    # Index defensively: a mutated/hostile bundle can carry an unhashable seq/id (a list) — skip those
    # here (the per-entry field-type gate below rejects them) rather than raising, so verify_disclosure
    # always returns a verdict instead of throwing on malformed input (php/js return a clean reject).
    # Only an integer id indexes a checkpoint by its value. Any other id (an object, a list, true, a string,
    # none) gets a name of its own, so that the type gate below rejects that checkpoint and no valid one can
    # take its place in the index. Until 2026-11-18 a checkpoint whose id could not be a key was left out of
    # the index, never looked at again, and the bundle passed without it.
    cp_by_id = {}
    for _i, _cp in enumerate(checkpoints):
        _cid = _cp.get("id")
        _plain = isinstance(_cid, int) and not isinstance(_cid, bool)
        cp_by_id[_cid if _plain else ("malformed", _i)] = _cp
    by_seq = {e.get("seq"): e for e in entries if isinstance(e, dict) and isinstance(e.get("seq"), int)}
    state = {"ok": True}
    cp_checks = []

    def cp_add(ok: bool, msg: str, fatal: bool):
        cp_checks.append({"ok": ok, "fatal": fatal, "msg": msg})
        if fatal and not ok:
            state["ok"] = False

    # Whose server key? The checkpoint signatures below verify under the key the BUNDLE carries. A
    # bundle rebuilt under another key agrees with itself just as well, so "signed by the server key"
    # means "signed by the key this bundle names" until that key is compared with one obtained
    # elsewhere. With an expected key the comparison is made here, and a bundle that carries another
    # key, or none, is rejected. Without one, the line says what was and was not shown. Compared as
    # decoded bytes. Mirrors verify.php and verifier.js.
    server_key_state = "absent"
    if expected_server_pubkey is not None:
        want, have = _key32(expected_server_pubkey), _key32(server_pub)
        server_key_state = "mismatch"
        if want is None:
            cp_add(False, "the expected server key is not a 32-byte Ed25519 key — rejected", True)
        elif server_pub is None:
            cp_add(False, "a server key was expected and this bundle carries none — its checkpoints cannot be shown to be that server's", True)
        elif have is None or have != want:
            cp_add(False, "the server key in this bundle is NOT the expected one — its checkpoint signatures are by another key", True)
        else:
            cp_add(True, "the server key in this bundle is the expected one", True)
            server_key_state = "expected"
    elif server_pub is not None:
        server_key_state = "unconfirmed"
        cp_add(True, f"server key {server_pub} is taken from this bundle: the checkpoint signatures below are by THAT key, "
                     "which this pass does not show to be Touchstone's — compare it with server_pubkey at "
                     f"/.well-known/touchstone/checkpoints/{recorder_id}, or verify again with the expected key", False)

    # Key epochs must be introduced by their key_rotation entry when it's in the bundle,
    # else an attacker injects a forged epoch (see verify.php). Genesis is bound by the PoP.
    for ep in epochs:
        try:
            if int(ep["from_seq"]) == 0:
                continue
            rot = by_seq.get(int(ep["from_seq"]) - 1)
            if rot is None:
                cp_add(True, f"key epoch from seq {ep['from_seq']} relies on a key_rotation entry not in this disclosure — verify the full chain", False)
                continue
            rb = {}
            if rot.get("body_enc"):
                try:
                    rb = json.loads(rot["body_enc"])
                except Exception:
                    rb = {}
            cp_add(rot.get("event_type") == "key_rotation" and rb.get("new_signing_pubkey") == ep["pubkey"],
                   f"key epoch from seq {ep['from_seq']} introduced by its key_rotation entry", True)
        except Exception:
            cp_add(False, "malformed key epoch — rejected", True)
    cp_add(True, f'attribution binds to the genesis key, which self-claims subject "{rec.get("subject_sub")}"; '
                 f'confirm that key at /.well-known/touchstone/pubkeys/{rec.get("subject_sub")} — this bundle alone '
                 "does not prove the subject→key binding", False)
    # The tier label is the same kind of claim: nothing in the bundle binds it. Say so beside it.
    if isinstance(rec.get("trust_tier"), str) and rec.get("trust_tier") != "":
        cp_add(True, f'trust tier "{rec.get("trust_tier")}" is this bundle\'s own statement, bound by no hash or signature in it — '
                     f"the recorder's public feed states it too (/.well-known/touchstone/checkpoints/{recorder_id}, field trust_tier)", False)

    prev_cp = None

    def _is_int(x):
        return isinstance(x, int) and not isinstance(x, bool)

    for cp in sorted(cp_by_id.values(), key=lambda c: c.get("seq_start", 0) if _is_int(c.get("seq_start")) else 0):
        try:
            # strict checkpoint field types — reject type-confused checkpoints uniformly
            # (matches verify.php / verifier.js).
            if not (_is_int(cp.get("id")) and _is_int(cp.get("seq_start")) and _is_int(cp.get("seq_end"))
                    and isinstance(cp.get("merkle_root"), str) and isinstance(cp.get("head_hash"), str)):
                cp_add(False, "malformed checkpoint field types — rejected", True)
                continue
            # The head is, by the server's rule, the hash of the entry the checkpoint ends at: its last entry, or for
            # a heartbeat, which adds none, the last entry before it (seq_end either way). No signature covers
            # head and root together, so when that entry is in the bundle the two are compared here. The entry
            # counts only when its own proof shows it is the last leaf under THIS root (no sibling on the right):
            # an entry can be restated at another seq by anyone, so one found by its seq alone proves nothing.
            # The entry lines further down hold seq_end to the same leaf. When the entry is not in the bundle,
            # nothing here can do either, and the line says so.
            last_e = by_seq.get(cp["seq_end"])
            if isinstance(last_e, dict) and _is_int(last_e.get("seq")) and last_e["seq"] == cp["seq_end"]:
                lp = last_e.get("merkle_proof")
                if isinstance(lp, dict) and not lp:
                    lp = []
                last_leaf_here = (isinstance(lp, list) and not any(not isinstance(st, dict) or st.get("side") == "right" for st in lp)
                                  and _merkle_from_proof(last_e.get("entry_hash"), lp) == cp["merkle_root"])
                if not last_leaf_here:
                    cp_add(False, f"checkpoint #{cp['id']}: the entry at seq {cp['seq_end']}, where it ends, is not shown to be the last leaf under its root", True)
                else:
                    cp_add(last_e["entry_hash"] == cp["head_hash"],
                           f"checkpoint #{cp['id']} head is the hash of the entry it ends at (seq {cp['seq_end']})", True)
            else:
                cp_add(True, f"checkpoint #{cp['id']}: the entry it ends at (seq {cp['seq_end']}) is not in this disclosure, "
                             f"so nothing here ties the head to an entry, and this checkpoint's anchors, which commit to the head, "
                             f"are not shown to cover the entries below", False)
            if server_pub:
                cp_add(_ed(server_pub, cp["merkle_root"], cp.get("recorder_sig", "")),
                       f"checkpoint #{cp['id']} root signed by "
                       + ("the expected server key" if server_key_state == "expected" else "the server key in this bundle"), True)
            else:
                cp_add(True, f"checkpoint #{cp['id']} server signature unverifiable (no server_pubkey)", False)
            if prev_cp is not None:
                if int(cp["seq_start"]) > int(prev_cp["seq_end"]) + 1:
                    cp_add(True, f"checkpoint #{cp['id']} follows #{prev_cp['id']} (intermediate checkpoints not in this disclosure)", False)
                else:
                    contig = int(cp["seq_start"]) == int(prev_cp["seq_end"]) + 1
                    linked = cp.get("prev_checkpoint_hash") and cp["prev_checkpoint_hash"] == prev_cp["head_hash"]
                    cp_add(bool(contig and linked), f"checkpoint #{cp['id']} extends #{prev_cp['id']} append-only", True)
            for w in (cp["witnesses"] if isinstance(cp.get("witnesses"), list) else []):
                msg = f"touchstone-cp-witness:v1:{recorder_id}:{cp['id']}:{cp['merkle_root']}:{cp['head_hash']}"
                cp_add(_ed(w["witness_pubkey"], msg, w["witness_sig"]),
                       f"checkpoint #{cp['id']} witnessed by {w['witness_sub']} ({w['grade']})", True)
            # RFC 3161: a carried response must commit to THIS head. Fails the checkpoint, not a note.
            for a in (cp["anchors"] if isinstance(cp.get("anchors"), list) else []):
                if not isinstance(a, dict) or a.get("method") != "tsa" or a.get("status") != "confirmed":
                    continue
                tb = tsa_anchor_binding(a, cp.get("head_hash"))
                if tb["state"] == "fail":
                    cp_add(False, f"RFC 3161 timestamp does not bind checkpoint #{cp['id']}: {tb['reason']}", True)
                elif tb["state"] == "bound":
                    cp_add(True, f"checkpoint #{cp['id']}: the carried RFC 3161 response's message imprint equals this head "
                                 f"({tb['host']}); the authority's signature and certificate chain are not checked here — openssl ts -verify", False)
                else:
                    cp_add(True, f"checkpoint #{cp['id']}: an RFC 3161 timestamp is claimed ({tb['host']}) but no response is carried, "
                                 f"so nothing here binds it to this head", False)
        except Exception:
            cp_add(False, "malformed checkpoint — rejected", True)
        prev_cp = cp

    # Committed beacon policy from the hash-committed genesis body: once a recorder declares
    # beacon_from_seq=N, every entry at seq>=N must carry a beacon — a missing one is a contradiction,
    # not a silence. Absent → no enforcement.
    beacon_from_seq = None
    _g = next((x for x in entries if x.get("seq") == 0 or x.get("event_type") == "genesis"), None)
    if _g and _g.get("body_enc"):
        try:
            _bc = json.loads(_g["body_enc"]).get("beacon_commitment")
            if isinstance(_bc, dict) and isinstance(_bc.get("from_seq"), int) and not isinstance(_bc.get("from_seq"), bool):
                beacon_from_seq = _bc["from_seq"]
        except Exception:
            pass

    entries_out = []
    for e in entries:
        checks = []

        def add(ok: bool, msg: str, fatal: bool):
            checks.append({"ok": ok, "fatal": fatal, "msg": msg})
            if fatal and not ok:
                state["ok"] = False

        # strict field types: reject type-confused entries uniformly instead of coercing.
        types_ok = isinstance(e.get("seq"), int) and not isinstance(e.get("seq"), bool) \
            and all(isinstance(e.get(f), str) for f in ("prev_hash", "entry_hash", "payload_hash", "actor_sub", "actor_sig"))
        if "counterparty_sub" in e and e["counterparty_sub"] is not None and not isinstance(e["counterparty_sub"], str):
            types_ok = False
        if not types_ok:
            add(False, "malformed entry field types — rejected", True)
            entries_out.append({"seq": e["seq"] if isinstance(e.get("seq"), int) else -1,
                                "type": str(e.get("event_type", "")), "redacted": False, "checks": checks})
            continue

        try:  # fail-closed: any malformed entry (missing field, bad type) → rejected
            add(_entry_hash(e) == e["entry_hash"], "entry_hash integrity", True)

            # beacon commitment: seq >= from_seq must be beacon-bound. A malformed beacon already fails
            # integrity above; this catches the ABSENT one (a valid legacy hash where policy required one).
            if beacon_from_seq is not None and e["seq"] >= beacon_from_seq:
                sb = e.get("server_beacon")
                bound = isinstance(sb, dict) and all(k in sb for k in ("chain", "round", "randomness"))
                add(bound, f"beacon commitment honored (seq >= {beacon_from_seq} is beacon-bound)", True)

            seq_key = key_for_seq(int(e["seq"]))
            if int(e["seq"]) == 0:
                challenge = "touchstone-pop:v1:" + rec["subject_sub"] + ":" + seq_key
                add(_ed(seq_key, challenge, e["actor_sig"]), "genesis proof-of-possession", True)
            else:
                add(_ed(seq_key, _signed_content(recorder_id, e), e["actor_sig"]), "actor signature (subject key)", True)

            if e.get("event_type") == "key_rotation" and e.get("body_enc"):
                try:
                    rb = json.loads(e["body_enc"])
                except Exception:
                    rb = {}
                np = rb.get("new_signing_pubkey", "")
                add(_ed(np, f"touchstone-rotate:v1:{recorder_id}:{np}", rb.get("new_key_pop", "")),
                    "key rotation → new key proof-of-possession", True)

            if e.get("counterparty_sig") and e.get("counterparty_pubkey"):
                add(_ed(e["counterparty_pubkey"], _signed_content(recorder_id, e), e["counterparty_sig"]),
                    f"counterparty co-signature ({e.get('counterparty_sub')}, {e.get('counterparty_grade', 'claimed')})", True)
            elif e.get("counterparty_sub"):
                add(True, f"names counterparty {e['counterparty_sub']} (awaiting co-signature)", False)

            if by_seq.get(e["seq"] - 1):
                add(e["prev_hash"] == by_seq[e["seq"] - 1]["entry_hash"], f"chain linkage to seq {e['seq'] - 1}", True)

            # merkle_proof is a list (possibly empty: a single-entry checkpoint's proof IS
            # empty, root == leaf) — run whenever present, matching verify.php/verifier.js. An
            # empty object {} is treated as an empty list (PHP can't tell {} from [] under
            # assoc decode, so all three normalize it the same way).
            mp = e.get("merkle_proof")
            if isinstance(mp, dict) and not mp:
                mp = []
            _cid = e.get("checkpoint_id")
            if isinstance(mp, list) and isinstance(_cid, int) and not isinstance(_cid, bool) and cp_by_id.get(_cid):
                cp = cp_by_id[e["checkpoint_id"]]
                included = _merkle_from_proof(e["entry_hash"], mp) == cp["merkle_root"]
                add(included, f"merkle inclusion in checkpoint #{cp['id']}", True)
                # Where the entry stands in its checkpoint. Its seq must lie in the range the checkpoint states, and
                # it is the entry the checkpoint ends at exactly when its proof has no sibling on the right: the tree
                # promotes a lone node, so only the last leaf has none. Nobody signs seq_end. This is what holds it,
                # and through it the head, to the signed root.
                if included and _is_int(cp.get("seq_start")) and _is_int(cp.get("seq_end")):
                    last_leaf = not any(isinstance(st, dict) and st.get("side") == "right" for st in mp)
                    if e["seq"] < cp["seq_start"] or e["seq"] > cp["seq_end"]:
                        add(False, f"seq {e['seq']} is outside checkpoint #{cp['id']}, which states seq {cp['seq_start']} to {cp['seq_end']}", True)
                    elif last_leaf and e["seq"] != cp["seq_end"]:
                        add(False, f"this entry is the last leaf under checkpoint #{cp['id']}'s root, and the checkpoint states that it ends at seq {cp['seq_end']}", True)
                    elif not last_leaf and e["seq"] == cp["seq_end"]:
                        add(False, f"checkpoint #{cp['id']} states that it ends at this entry, and the entry's proof shows a later leaf under the same root", True)
                any_confirmed = False
                for a in (cp.get("anchors") or []):
                    if not isinstance(a, dict):
                        continue
                    try:
                        blob = json.loads(a.get("token_blob") or "{}")
                    except Exception:
                        blob = {}
                    if a.get("method") == "self" and a.get("status") == "confirmed":
                        # verify the server signed the head — don't trust the status label
                        self_ok = _ed(server_pub, cp["head_hash"], a.get("token_blob", "")) if server_pub else None
                        if self_ok is False:
                            add(False, f"self anchor signature INVALID (checkpoint #{cp['id']})", True)
                        else:
                            add(True, f"anchored (self, {a.get('external_ts')})" + (" — server signature verified" if self_ok else ""), False)
                            any_confirmed = True
                    elif a.get("method") == "ots" and a.get("status") == "confirmed" and blob.get("bitcoin_height"):
                        # The height is the SERVER'S claim; this offline check does not confirm the
                        # proof commits to that block. (Self anchors above are signature-verified;
                        # OTS needs Bitcoin, which is out of scope for an offline tool.) Say so, and
                        # point at how to confirm it — don't present a claim as a verified fact.
                        add(True, f"OTS → Bitcoin block {blob['bitcoin_height']} CLAIMED ({a.get('external_ts')}) "
                                  f"— not confirmed against mainnet here; verify the downloadable .ots with "
                                  f"`ots verify`, which recomputes the committed root against the real block", False)
                        any_confirmed = True
                    elif a.get("method") == "ots":
                        add(True, "OTS submitted, Bitcoin-pending (re-check with ots upgrade/verify)", False)
                    elif a.get("method") == "tsa" and a.get("status") == "confirmed":
                        tb = tsa_anchor_binding(a, cp.get("head_hash"))
                        if tb["state"] == "fail":
                            add(False, f"RFC 3161 timestamp does not bind checkpoint #{cp['id']}: {tb['reason']}", True)
                        elif tb["state"] == "bound":
                            add(True, f"RFC 3161 timestamp: the carried response commits to this head. The authority's name ({tb['host']}) "
                                      f"and the time ({a.get('external_ts')}) are this bundle's own statements, and the authority's signature "
                                      f"is not checked here — openssl ts -verify", False)
                            any_confirmed = True
                        else:
                            add(False, f"RFC 3161 timestamp claimed ({tb['host']}, {a.get('external_ts')}) but no response is carried; "
                                       f"not counted as an anchor", False)
                if not any_confirmed:
                    add(False, "no confirmed external anchor yet", False)
            else:
                add(False, "not yet checkpointed/anchored (integrity+signature only)", False)

            if e.get("sd"):
                _rev = e.get("sd_revealed")
                revealed = _rev if isinstance(_rev, list) else []  # non-list → nothing revealed (matches verify.php/js)
                committed = None
                ks = e.get("sd_keyset")
                if isinstance(ks, dict) and ks:  # empty {} → treat as no key-set commitment (matches verify.php)
                    keys = sorted(ks["keys"] if isinstance(ks.get("keys"), list) else [])
                    ks_leaf = _sha256_hex(("tsd:keyset:v1\n" + jcs(keys)).encode("utf-8"))
                    add(_merkle_from_proof(ks_leaf, ks.get("proof", [])) == e["payload_hash"],
                        f"selective-disclosure key-set committed ({len(keys)} fields)", True)
                    committed = keys
                for f in revealed:
                    leaf = _sha256_hex(("tsd:field:v1\n" + jcs([f["k"], f["v"], f["s"]])).encode("utf-8"))
                    add(_merkle_from_proof(leaf, f.get("proof", [])) == e["payload_hash"],
                        f'selective field "{f["k"]}" proven in payload_hash', True)
                    if committed is not None:
                        add(f["k"] in committed, f'revealed field "{f["k"]}" in committed key-set', True)
                shown = len(revealed)
                if committed is not None:
                    revealed_keys = [f["k"] for f in revealed]
                    withheld = [k for k in committed if k not in revealed_keys]
                    add(True, f"selective disclosure: {shown} of {len(committed)} committed field(s) revealed; "
                              f"withheld (provably sealed): {', '.join(withheld) or 'none'}", False)
                else:
                    count = e.get("sd_field_count", 0)
                    add(True, f"selective disclosure: {shown} of {count} field(s) revealed (key-set not committed)", False)
        except Exception:
            add(False, "malformed entry — rejected", True)

        _seq = e.get("seq")
        entries_out.append({"seq": _seq if isinstance(_seq, int) else -1, "type": e.get("event_type", ""),
                            "redacted": bool(e.get("redacted")), "checks": checks})

    return {
        "ok": state["ok"], "format_ok": True, "recorder": recorder_id,
        "subject": rec.get("subject_sub"), "tier": rec.get("trust_tier"),
        "server_key": {"state": server_key_state, "pubkey": server_pub},
        "entries": entries_out, "checkpoints": cp_checks,
    }
