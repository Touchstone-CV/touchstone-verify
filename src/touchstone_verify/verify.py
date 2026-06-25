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


def _merkle_from_proof(leaf_hex: str, proof) -> str:
    cur = _mleaf(leaf_hex)
    for step in proof:
        cur = _mnode(cur, step["hash"]) if step.get("side") == "right" else _mnode(step["hash"], cur)
    return cur


def _entry_hash(e) -> str:
    s = "\n".join([
        str(e["seq"]), e["prev_hash"], e["server_ts"], e["payload_hash"],
        e["actor_sub"], e.get("counterparty_sub") or "", e["actor_sig"],
    ])
    return _sha256_hex(s.encode("utf-8"))


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

    rec = b["recorder"]
    recorder_id = rec["public_id"]
    pubkey = rec["signing_pubkey"]
    epochs = sorted(rec.get("signing_keys", []), key=lambda x: int(x["from_seq"]))

    def key_for_seq(seq: int) -> str:
        k = pubkey
        for ep in epochs:
            if int(ep["from_seq"]) <= seq:
                k = ep["pubkey"]
            else:
                break
        return k

    server_pub = b.get("server_pubkey")
    cp_by_id = {cp["id"]: cp for cp in b.get("checkpoints", [])}
    by_seq = {e["seq"]: e for e in b["entries"]}
    state = {"ok": True}
    cp_checks = []

    def cp_add(ok: bool, msg: str, fatal: bool):
        cp_checks.append({"ok": ok, "fatal": fatal, "msg": msg})
        if fatal and not ok:
            state["ok"] = False

    prev_cp = None
    for cp in sorted(cp_by_id.values(), key=lambda c: c.get("seq_start", 0)):
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
        for w in cp.get("witnesses", []):
            msg = f"touchstone-cp-witness:v1:{recorder_id}:{cp['id']}:{cp['merkle_root']}:{cp['head_hash']}"
            cp_add(_ed(w["witness_pubkey"], msg, w["witness_sig"]),
                   f"checkpoint #{cp['id']} witnessed by {w['witness_sub']} ({w['grade']})", True)
        prev_cp = cp

    entries_out = []
    for e in b["entries"]:
        checks = []

        def add(ok: bool, msg: str, fatal: bool):
            checks.append({"ok": ok, "fatal": fatal, "msg": msg})
            if fatal and not ok:
                state["ok"] = False

        add(_entry_hash(e) == e["entry_hash"], "entry_hash integrity", True)

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

        if e.get("merkle_proof") and e.get("checkpoint_id") is not None and cp_by_id.get(e["checkpoint_id"]):
            cp = cp_by_id[e["checkpoint_id"]]
            add(_merkle_from_proof(e["entry_hash"], e["merkle_proof"]) == cp["merkle_root"],
                f"merkle inclusion in checkpoint #{cp['id']}", True)

        if e.get("sd"):
            for f in e.get("sd_revealed", []):
                leaf = _sha256_hex(("tsd:field:v1\n" + jcs([f["k"], f["v"], f["s"]])).encode("utf-8"))
                add(_merkle_from_proof(leaf, f.get("proof", [])) == e["payload_hash"],
                    f'selective field "{f["k"]}" proven in payload_hash', True)
            shown = len(e.get("sd_revealed", []))
            count = e.get("sd_field_count", 0)
            add(True, f"selective disclosure: {shown} of {count} field(s) revealed, {count - shown} withheld", False)

        entries_out.append({"seq": int(e["seq"]), "type": e.get("event_type", ""),
                            "redacted": bool(e.get("redacted")), "checks": checks})

    return {
        "ok": state["ok"], "format_ok": True, "recorder": recorder_id,
        "subject": rec.get("subject_sub"), "tier": rec.get("trust_tier"),
        "entries": entries_out, "checkpoints": cp_checks,
    }
