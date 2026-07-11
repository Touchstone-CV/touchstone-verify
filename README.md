# touchstone-verify

Independently verify a **[Touchstone](https://touchstone.cv)** disclosure — in pure Python,
with **zero dependencies**. Read it before you trust it: it's a small, self-contained file.

A disclosure is a tamper-evident slice of an agent's action log. This package re-derives,
with no trust in Touchstone, that the slice is **intact** (entry hashes recompute), **attributed**
(the subject's Ed25519 signature holds, epoch-aware across key rotation), and **ordered**
(hash-chained, with checkpoints that are append-only, server-signed, and witness-co-signed). It
also checks **selective-disclosure** field proofs and reports the external anchors. It proves
tampering by anyone who is not Touchstone — it does **not** prove completeness, and says so.

It agrees byte-for-byte with the other two Touchstone verifiers (`verify.php`, `verifier.js`):
all three are tested against the same conformance corpus.

## Install

```bash
pip install touchstone-verify
```

## Use

Command line — pass a file, a URL, or a disclosure token:

```bash
touchstone-verify https://touchstone.cv/d/833cd4ca23fbb940dd71843ca47a807e
touchstone-verify ./bundle.json
touchstone-verify 833cd4ca23fbb940dd71843ca47a807e        # fetches from touchstone.cv
```

Exit code `0` = verified, `1` = a load-bearing check failed, `2` = couldn't load.

Library:

```python
from touchstone_verify import verify_disclosure
import json, urllib.request

bundle = json.load(urllib.request.urlopen("https://touchstone.cv/d/<token>"))
result = verify_disclosure(bundle)
print(result["ok"])           # True / False
for e in result["entries"]:
    for c in e["checks"]:
        print(c["ok"], c["msg"])
```

### Grade a receipt's columns by k

```python
from touchstone_verify import grade_columns, find_columns
import json, urllib.request

doc = json.load(urllib.request.urlopen("https://touchstone.cv/columns/<recorder>/<seq>"))
cols, digest = find_columns(doc)
r = grade_columns(cols, digest)
print(r["coherent"], r["min_k"])     # True / cheapest falsehood path (min k across load-bearing columns)
```

`k` is the minimum number of independent parties who must collude before a column can be false,
**computed from the evidence** (never the declared grade): `k=0` re-derivable, `k = 1 + distinct-control
witnesses` (co-sigs collapse on a shared key or a receipt-carried controller binding, so it's an
upper bound), `k=1` testimony. Declaring more strength than the evidence supports fails closed.

## What it checks

- **Integrity** — every `entry_hash` recomputes from its fields, **including the beacon fold**: a
  `beacon_binding` recorder's entries carry `server_beacon = {chain, round, randomness}` as a final
  `beacon:<chain>:<round>:<randomness>` line of the preimage (a checkable not-before). Absent → the
  exact legacy 7-field preimage, so older entries verify unchanged.
- **Attribution** — the subject signature verifies over the canonical signed content; genesis
  proof-of-possession; `key_rotation` new-key PoP; counterparty co-signatures.
- **Ordering** — `prev_hash` chain linkage; Merkle inclusion in the cited checkpoint.
- **Checkpoints** — server signature over each Merkle root; append-only linkage between
  consecutive checkpoints; independent witness co-signatures.
- **Selective disclosure** — each revealed field proves Merkle inclusion in `payload_hash`;
  withheld fields never appear in the bundle.

For split-view / Bitcoin-anchor cross-checking across independent relays, see the companion
`gossip_check.py` at <https://touchstone.cv/gossip_check.py>.

## License

[Apache-2.0](./LICENSE).
