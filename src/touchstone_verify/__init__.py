"""touchstone-verify — independently verify a Touchstone disclosure, zero dependencies.

    from touchstone_verify import verify_disclosure
    result = verify_disclosure(bundle_dict)   # {"ok": True/False, "entries": [...], ...}

    from touchstone_verify import grade_columns
    graded = grade_columns(columns_list)      # {"coherent": bool, "min_k": int|None, ...}
"""
from .columns import evaluate_column, find_columns, grade_columns
from .verify import jcs, verify_disclosure

__all__ = ["verify_disclosure", "jcs", "grade_columns", "evaluate_column", "find_columns"]
__version__ = "0.4.0"
