"""Grade a Touchstone receipt's `columns` by k — the minimum number of independent parties who must
collude before a column can be false — computed from the evidence, never the declared grade.

The pip-installable twin of touchstone.cv/columns-verify.py and verifier.js's verifyColumns(); it
reuses this package's JCS + Ed25519 so all impls agree byte-for-byte.

  - k = 0  DERIVABLE   value recomputes from its published input (value == alg(input)); uncollusible.
  - k >= 2 WITNESSED   counterparty co-signature(s) over the PROPOSITION. k = 1 + distinct-CONTROL
                       clusters: witnesses collapse when they share a signing key OR a receipt-carried,
                       verified controller binding (`controller = {pubkey, sig}` over
                       `touchstone-control:v1\\n<witness_pubkey>`). So k is an UPPER BOUND — undisclosed
                       shared control leaves no bytes and can only make the true k fewer.
  - k = 1  TESTIMONY   the attester's word alone; displayed, never counted as verified.

Fail closed: a k=0 that doesn't reproduce, a witnessed column whose signature doesn't verify, or a
column DECLARING more strength than its evidence supports (rank k=0 as infinity) -> the receipt is
incoherent. The rollup reports the MINIMUM k across load-bearing columns (the cheapest falsehood path).

    from touchstone_verify import grade_columns
    r = grade_columns([...])          # {"coherent": bool, "min_k": int|None, "columns": [...]}
"""
from .verify import jcs, _ed, _sha256_hex


def _recompute(col):
    d = col.get("derivation")
    if not isinstance(d, dict):
        return None
    alg, inp = d.get("alg"), d.get("input")
    if alg == "sha256":
        return isinstance(inp, str) and col.get("value") == _sha256_hex(inp.encode("utf-8"))
    if alg == "jcs-sha256":
        return col.get("value") == _sha256_hex(jcs(inp).encode("utf-8"))
    return False   # unknown alg -> cannot recompute -> fail closed


def _control_key(w):
    """A witness's control identity: a verified controller binding if carried, else its own key."""
    ctrl = w.get("controller")
    if isinstance(ctrl, dict) and ctrl.get("pubkey") and ctrl.get("sig"):
        if _ed(ctrl["pubkey"], "touchstone-control:v1\n" + str(w.get("pubkey")), ctrl["sig"]):
            return "ctrl:" + str(ctrl["pubkey"])
    return "key:" + str(w.get("pubkey"))


def _control_clusters(col):
    """Distinct-control clusters among valid co-signatures over the proposition (an upper bound on
    independent witnesses). A witness counts only for a signature over {proposition, value, challenge}
    — never for merely naming a key."""
    prop, val = col.get("proposition"), col.get("value")
    witnesses = col.get("witnesses")
    if witnesses is None and isinstance(col.get("witness"), dict):
        witnesses = [col["witness"]]
    clusters = set()
    for w in witnesses or []:
        if not isinstance(w, dict) or not w.get("pubkey") or not w.get("sig"):
            continue
        msg = jcs({"proposition": prop, "value": val, "challenge": w.get("challenge")})
        if _ed(w["pubkey"], msg, w["sig"]):
            clusters.add(_control_key(w))
    return len(clusters)


def evaluate_column(col):
    """Grade one column -> {ok: True/False/None, status, k, k_indep, note}."""
    declared = col.get("k")
    name = col.get("name")
    rec = _recompute(col)
    if rec is True:
        k, status = 0, "DERIVABLE"
    elif rec is False:
        return {"ok": False, "status": "RECOMPUTE-FAILS", "k": None, "k_indep": None, "name": name,
                "note": "declares a derivation but it does not reproduce the value"}
    else:
        clusters = _control_clusters(col)
        if clusters:
            k, status = 1 + clusters, "WITNESSED"
        else:
            k, status = 1, "TESTIMONY"
    # Over-claim = declaring more strength than earned. k=1 weakest, higher stronger, k=0 strongest
    # (uncollusible) -> rank k=0 as infinity.
    def _rank(x):
        return float("inf") if x == 0 else x

    if isinstance(declared, int) and _rank(declared) > _rank(k):
        return {"ok": False, "status": "OVER-CLAIMED", "k": k, "k_indep": k, "name": name,
                "note": "declares k=%d but the evidence supports only k=%d" % (declared, k)}
    if status == "DERIVABLE":
        note = "recomputed from published input — no coalition can forge it"
    elif status == "WITNESSED":
        note = ("<= %d distinct-control witness(es) co-signed the proposition (collapsed on shared "
                "key/controller); hidden shared control can only lower it" % (k - 1))
    else:
        note = "attester's word alone — believed, not checked"
    return {"ok": None if status == "TESTIMONY" else True, "status": status, "k": k, "k_indep": k,
            "note": note, "name": col.get("name"), "proposition": col.get("proposition")}


def grade_columns(columns, columns_sha256=None):
    """Grade a `columns` list. Returns {coherent, min_k, n_fail, columns:[...], digest_ok}.

    min_k is the cheapest falsehood path (min k over load-bearing columns; k=0 offers no path and is
    excluded). If columns_sha256 is given, it must equal sha256(JCS(columns)) or the receipt is not
    coherent (mutating even a testimony column is caught)."""
    out, n_fail, min_k = [], 0, None
    for col in columns:
        r = evaluate_column(col if isinstance(col, dict) else {})
        out.append(r)
        if r["ok"] is False:
            n_fail += 1
            continue
        if r["k"] is not None and r["k"] >= 1:
            min_k = r["k"] if min_k is None else min(min_k, r["k"])
    digest_ok = True
    if columns_sha256 is not None:
        digest_ok = _sha256_hex(jcs(columns).encode("utf-8")) == columns_sha256
    return {"coherent": n_fail == 0 and digest_ok, "min_k": min_k, "n_fail": n_fail,
            "digest_ok": digest_ok, "columns": out}


def find_columns(doc):
    """Locate a columns block at .columns / .payload.columns / .document.columns, plus any
    columns_sha256 sibling. Returns (columns_list_or_None, columns_sha256_or_None)."""
    for get in (lambda d: d.get("columns"),
                lambda d: (d.get("payload") or {}).get("columns"),
                lambda d: (d.get("document") or {}).get("columns")):
        try:
            c = get(doc)
        except Exception:
            c = None
        if isinstance(c, list):
            return c, (doc.get("columns_sha256") if isinstance(doc, dict) else None)
    return None, None
