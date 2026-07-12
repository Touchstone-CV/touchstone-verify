"""touchstone-verify — the Touchstone SDK: independently VERIFY a disclosure (zero dependencies), and
MINT one (needs the [record] extra for an Ed25519 signer).

    from touchstone_verify import verify_disclosure
    result = verify_disclosure(bundle_dict)   # {"ok": True/False, "entries": [...], ...}

    from touchstone_verify import grade_columns
    graded = grade_columns(columns_list)      # {"coherent": bool, "min_k": int|None, ...}

    from touchstone_verify import Recorder    # producer half — pip install "touchstone-verify[record]"
    rc = Recorder.from_env().record({"kind": "invoice", "amount": 100}, event_type="invoice")
    rc.wait_for_anchor(); rc.verify()         # mint → anchor → verify, one crypto core

Verify is pure-Python and dependency-free; only minting (record) pulls PyNaCl, and only when you use it.
"""
from .columns import evaluate_column, find_columns, grade_columns
from .record import Recorder, Receipt, payload_hash
from .verify import jcs, verify_disclosure

__all__ = ["verify_disclosure", "jcs", "grade_columns", "evaluate_column", "find_columns",
           "Recorder", "Receipt", "payload_hash"]
__version__ = "0.5.0"
