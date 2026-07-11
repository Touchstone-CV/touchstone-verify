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


def _mleaf(hex_h: str) -> str:
    return _sha256_hex(b"\x00" + bytes.fromhex(hex_h))


def _mnode(l: str, r: str) -> str:
    return _sha256_hex(b"\x01" + bytes.fromhex(l) + bytes.fromhex(r))


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


def verify_disclosure(b: dict) -> dict:
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
    cp_by_id = {cp.get("id"): cp for cp in checkpoints if isinstance(cp, dict) and isinstance(cp.get("id"), (int, str, type(None)))}
    by_seq = {e.get("seq"): e for e in entries if isinstance(e, dict) and isinstance(e.get("seq"), int)}
    state = {"ok": True}
    cp_checks = []

    def cp_add(ok: bool, msg: str, fatal: bool):
        cp_checks.append({"ok": ok, "fatal": fatal, "msg": msg})
        if fatal and not ok:
            state["ok"] = False

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
                prev_cp = cp
                continue
            if server_pub:
                cp_add(_ed(server_pub, cp["merkle_root"], cp.get("recorder_sig", "")),
                       f"checkpoint #{cp['id']} root signed by Touchstone server", True)
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
                add(_merkle_from_proof(e["entry_hash"], mp) == cp["merkle_root"],
                    f"merkle inclusion in checkpoint #{cp['id']}", True)
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
                        add(True, f"RFC 3161 timestamp ({a.get('external_ts')}); cryptographic check: openssl ts -verify", False)
                        any_confirmed = True
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
        "entries": entries_out, "checkpoints": cp_checks,
    }
