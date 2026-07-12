"""touchstone_verify.record — mint an anchored Touchstone receipt (the producer half of the SDK).

Verification in this package is zero-dependency; MINTING needs an Ed25519 *signing* key, which the
vendored verify-only curve code can't do, so it uses PyNaCl:  pip install "touchstone-verify[record]".

    from touchstone_verify import Recorder
    r = Recorder.from_env()                        # TOUCHSTONE_RECORDER/_API_KEY/_SUBJECT/_SIGNING_KEY
    rc = r.record({"kind": "invoice", "amount": 100}, event_type="invoice")
    rc.wait_for_anchor()                           # blocks until the next checkpoint sweeps this seq
    print(rc.verify())                             # payload_hash → entry_hash → checkpoint root

The key never leaves this process, and canonicalization happens locally (reusing the SAME jcs /
_signed_content / _entry_hash / _merkle_from_proof as verify_disclosure — one crypto core, no drift),
so a malicious server cannot trick you into signing a different commitment than you intended.
Receipt.local_entry_hash_ok() gives an IMMEDIATE positive confirmation that the server's entry_hash
matches the one you'd compute (for a non-beacon recorder); the AUTHORITATIVE, fail-closed check is
Receipt.verify() against the Bitcoin-anchored inclusion proof.
"""
import os
import json
import time
import base64
import urllib.request
import urllib.error

from .verify import jcs, _sha256_hex, _entry_hash, _signed_content, _merkle_from_proof

DEFAULT_BASE = "https://touchstone.cv"


def payload_hash(body) -> str:
    """sha256(JCS(body)) — the digest the entry commits to (recompute it to verify)."""
    return _sha256_hex(jcs(body).encode("utf-8"))


def _sign(seed_b64: str, msg: bytes) -> str:
    try:
        from nacl.signing import SigningKey
    except ImportError as e:  # pragma: no cover - exercised only without the extra installed
        raise RuntimeError("minting needs an Ed25519 signer — pip install \"touchstone-verify[record]\"") from e
    return base64.b64encode(SigningKey(base64.b64decode(seed_b64)).sign(msg).signature).decode()


def _http(method, url, api_key=None, body=None, timeout=30):
    headers = {"Accept": "application/json", "User-Agent": "touchstone-verify-record/1"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    if api_key:
        headers["Authorization"] = "Bearer " + api_key
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class Receipt:
    """The result of an append: the server's assignment + everything needed to verify it later."""

    def __init__(self, recorder, seq, prev_hash, entry_hash, server_ts, ph, actor_sub, counterparty_sub, actor_sig):
        self.recorder, self.seq, self.prev_hash = recorder, seq, prev_hash
        self.entry_hash, self.server_ts, self.payload_hash = entry_hash, server_ts, ph
        self.actor_sub, self.counterparty_sub, self.actor_sig = actor_sub, counterparty_sub, actor_sig

    @property
    def entry_url(self) -> str:
        return "%s/.well-known/touchstone/checkpoints/%s/entry/%d" % (
            self.recorder.base, self.recorder.recorder_id, self.seq)

    def _as_entry(self, server_beacon=None):
        return {"seq": self.seq, "prev_hash": self.prev_hash, "server_ts": self.server_ts,
                "payload_hash": self.payload_hash, "actor_sub": self.actor_sub,
                "counterparty_sub": self.counterparty_sub, "actor_sig": self.actor_sig,
                "server_beacon": server_beacon}

    def local_entry_hash_ok(self):
        """Recompute entry_hash from the server's response. True if it matches (server didn't misreport);
        None when it can't be decided locally (a beacon-bound recorder folds a server_beacon line absent
        from the append response — verify() settles it against the anchored inclusion proof)."""
        return True if _entry_hash(self._as_entry()) == self.entry_hash else None

    def wait_for_anchor(self, timeout=1200, poll=15):
        """Block until this seq is checkpointed (its inclusion proof becomes fetchable). Needs the
        recorder to serve public inclusion proofs. Returns the inclusion-proof dict."""
        deadline = time.time() + timeout
        while True:
            try:
                return _http("GET", self.entry_url)
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise
            if time.time() >= deadline:
                raise TimeoutError("seq %d not checkpointed within %ds (or recorder not inclusion-public)"
                                   % (self.seq, timeout))
            time.sleep(poll)

    def verify(self):
        """Walk the receipt: payload_hash → entry_hash → checkpoint Merkle root, reusing the package's
        own verify primitives. `ots verify` the checkpoint with your node to finish the walk to Bitcoin."""
        try:
            proof = _http("GET", self.entry_url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"ok": False, "reason": "not yet checkpointed (or recorder not inclusion-public) — wait_for_anchor()"}
            raise
        entry, cp = proof.get("entry") or {}, proof.get("checkpoint") or {}
        eh_ok = _entry_hash(entry) == entry.get("entry_hash")
        root_ok = _merkle_from_proof(entry.get("entry_hash"), proof.get("inclusion_proof") or []) == cp.get("merkle_root")
        ph_ok = entry.get("payload_hash") == self.payload_hash
        return {
            "ok": bool(eh_ok and root_ok and ph_ok),
            "payload_hash_matches": ph_ok, "entry_hash_recompute": eh_ok, "folds_to_checkpoint": root_ok,
            "checkpoint": cp.get("id"), "merkle_root": cp.get("merkle_root"),
            "bitcoin": (cp.get("bitcoin") or {}).get("height"),
            "finish": "ots verify the checkpoint (%s) with your own node" % cp.get("ots"),
        }


class Recorder:
    """A recorder you can append to: its public id + an append-scoped API key + the subject signing key."""

    def __init__(self, recorder_id, api_key, subject_sub, signing_key_b64, base=DEFAULT_BASE):
        self.recorder_id, self.api_key = recorder_id, api_key
        self.subject_sub, self.signing_key_b64 = subject_sub, signing_key_b64
        self.base = base.rstrip("/")

    @classmethod
    def from_env(cls):
        """Read TOUCHSTONE_RECORDER / _API_KEY / _SUBJECT / _SIGNING_KEY (or _KEY_FILE={"seed_b64":…})."""
        seed = os.environ.get("TOUCHSTONE_SIGNING_KEY")
        if not seed and os.environ.get("TOUCHSTONE_KEY_FILE"):
            with open(os.environ["TOUCHSTONE_KEY_FILE"], encoding="utf-8") as f:
                seed = json.load(f).get("seed_b64")
        need = {"TOUCHSTONE_RECORDER": os.environ.get("TOUCHSTONE_RECORDER"),
                "TOUCHSTONE_API_KEY": os.environ.get("TOUCHSTONE_API_KEY"),
                "TOUCHSTONE_SUBJECT": os.environ.get("TOUCHSTONE_SUBJECT"), "signing key": seed}
        missing = [k for k, v in need.items() if not v]
        if missing:
            raise RuntimeError("missing config: " + ", ".join(missing))
        return cls(need["TOUCHSTONE_RECORDER"], need["TOUCHSTONE_API_KEY"], need["TOUCHSTONE_SUBJECT"], seed,
                   os.environ.get("TOUCHSTONE_BASE_URL", DEFAULT_BASE))

    def record(self, payload, event_type="custom", counterparty_sub=None, client_ts=None):
        """Sign `payload` locally and append it. Returns a Receipt. The authoritative, fail-closed check
        is Receipt.verify() once the entry is anchored; Receipt.local_entry_hash_ok() is an immediate
        positive confirmation for a non-beacon recorder."""
        ph = payload_hash(payload)
        msg = _signed_content(self.recorder_id, {
            "event_type": event_type, "actor_sub": self.subject_sub,
            "counterparty_sub": counterparty_sub, "payload_hash": ph, "client_ts": client_ts,
        }).encode("utf-8")
        body = {"event_type": event_type, "payload_hash": ph, "actor_sig": _sign(self.signing_key_b64, msg)}
        if counterparty_sub is not None:
            body["counterparty_sub"] = counterparty_sub
        if client_ts is not None:
            body["client_ts"] = client_ts
        res = _http("POST", "%s/api/v1/recorders/%s/entries" % (self.base, self.recorder_id), self.api_key, body)
        return Receipt(self, res["seq"], res["prev_hash"], res["entry_hash"], res["server_ts"],
                       ph, self.subject_sub, counterparty_sub, body["actor_sig"])
