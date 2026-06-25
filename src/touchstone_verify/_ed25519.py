"""Pure-Python Ed25519 signature verification (RFC 8032 reference).

Vendored so the verifier has zero dependencies — an auditor reads this file rather
than trusting a compiled crypto library. Verify-only; no signing, no secret handling.
"""
import hashlib

_p = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


def _x_recover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = (4 * _inv(5)) % _p
_Bx = _x_recover(_By)
_B = (_Bx % _p, _By % _p, 1, (_Bx * _By) % _p)  # extended coords (X, Y, Z, T)


def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _p
    b = ((y1 + x1) * (y2 + x2)) % _p
    c = (t1 * 2 * _d * t2) % _p
    dd = (z1 * 2 * z2) % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return ((e * f) % _p, (g * h) % _p, (f * g) % _p, (e * h) % _p)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encode_point(P) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x = (x * zi) % _p
    y = (y * zi) % _p
    val = y | ((x & 1) << 255)
    return val.to_bytes(32, "little")


def _decode_point(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _x_recover(y)
    if x & 1 != (int.from_bytes(s, "little") >> 255) & 1:
        x = _p - x
    P = (x % _p, y % _p, 1, (x * y) % _p)
    if not _on_curve(P):
        raise ValueError("point not on curve")
    return P


def _on_curve(P) -> bool:
    x, y, z, t = P
    zi = _inv(z)
    x = (x * zi) % _p
    y = (y * zi) % _p
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _p == 0


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` (64 bytes) is a valid Ed25519 signature of `message`
    under `public_key` (32 bytes)."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        A = _decode_point(public_key)
        R = signature[:32]
        s = int.from_bytes(signature[32:], "little")
        if s >= _L:
            return False
        h = int.from_bytes(_sha512(R + public_key + message), "little") % _L
        left = _scalarmult(_B, s)
        right = _edwards_add(_decode_point(R), _scalarmult(A, h))
        return _encode_point(left) == _encode_point(right)
    except Exception:
        return False
