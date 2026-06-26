"""touchstone-verify — independently verify a Touchstone disclosure, zero dependencies.

    from touchstone_verify import verify_disclosure
    result = verify_disclosure(bundle_dict)   # {"ok": True/False, "entries": [...], ...}
"""
from .verify import jcs, verify_disclosure

__all__ = ["verify_disclosure", "jcs"]
__version__ = "0.2.0"
