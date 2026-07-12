"""Producer (record) tests — dep-free (run: python tests/test_record.py).

The producer half must sign the EXACT bytes the server and verify_disclosure reconstruct, so it reuses
verify.py's jcs / _signed_content / _entry_hash (one crypto core). These assert the canonical forms are
byte-exact and that a Receipt round-trips through the same primitives — no network, no PyNaCl (signing
itself is exercised live; here we pin the bytes an entry commits to).
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from touchstone_verify import Recorder, Receipt, payload_hash  # noqa: E402
from touchstone_verify.verify import _entry_hash, _signed_content  # noqa: E402


def test_payload_hash_is_sha256_of_jcs():
    assert payload_hash({"b": 2, "a": 1}) == hashlib.sha256(b'{"a":1,"b":2}').hexdigest()


def test_signed_content_shape():
    # every field present; null (not omitted) for unused counterparty_sub / client_ts.
    sc = _signed_content("rec_x", {"event_type": "note", "actor_sub": "s", "counterparty_sub": None,
                                   "payload_hash": "ph", "client_ts": None})
    assert sc == ('{"actor_sub":"s","client_ts":null,"counterparty_sub":null,"event_type":"note",'
                  '"payload_hash":"ph","recorder_id":"rec_x","v":1}')


def test_receipt_local_entry_hash_recompute():
    r = Recorder("rec_x", "tsk_x", "sub-1", "AAA", base="https://touchstone.cv")
    # a consistent (seq, prev, ts, ph, actor, cp, sig) whose entry_hash we compute the canonical way…
    fields = dict(seq=1, prev_hash="00", server_ts="2026-01-01T00:00:00+00:00",
                  payload_hash="ph", actor_sub="sub-1", counterparty_sub=None, actor_sig="sig")
    eh = _entry_hash({**fields, "server_beacon": None})
    rc = Receipt(r, fields["seq"], fields["prev_hash"], eh, fields["server_ts"], fields["payload_hash"],
                 fields["actor_sub"], fields["counterparty_sub"], fields["actor_sig"])
    assert rc.local_entry_hash_ok() is True
    # a mismatch is inconclusive locally (could be a beacon recorder, whose fold line isn't in the append
    # response) — None, not a false alarm. The authoritative fail-closed check is verify() vs the anchor.
    bad = Receipt(r, 1, "00", "deadbeef" * 8, fields["server_ts"], "ph", "sub-1", None, "sig")
    assert bad.local_entry_hash_ok() is None


def test_entry_url():
    r = Recorder("rec_abc", "k", "s", "AAA", base="https://touchstone.cv/")
    rc = Receipt(r, 7, "p", "h", "t", "ph", "s", None, "sig")
    assert rc.entry_url == "https://touchstone.cv/.well-known/touchstone/checkpoints/rec_abc/entry/7"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print("ok  %s" % fn.__name__)
    print("\nALL %d RECORD TESTS PASSED" % len(fns))
