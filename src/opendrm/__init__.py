"""opendrm: sign playback tokens in your backend.

When a viewer presses play, your backend already knows who they are and what
they paid for. It signs a short-lived token saying so, hands it to the player,
and the player sends it to opendrm with the license request.

    from opendrm import playback_token

    token = playback_token(
        secret=settings.OPENDRM_TOKEN_SECRET,
        user=request.user.id,
        title="ip-c3",
        device=request.headers.get("X-Device-Id"),
        claims={"plan": "paid"},
    )

Standard library only. The token is an HS256 JWT.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Mapping, Optional, Union

__all__ = ["playback_token", "RESERVED_CLAIMS"]
__version__ = "0.1.0"

#: Claims set by playback_token itself; pass them as arguments, not in ``claims``.
RESERVED_CLAIMS = frozenset({"sub", "title", "device", "iat", "exp"})


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def playback_token(
    secret: Union[str, bytes],
    user: Union[str, int],
    title: str,
    claims: Optional[Mapping[str, Any]] = None,
    device: Optional[str] = None,
    ttl: int = 60,
    now: Optional[float] = None,
) -> str:
    """Return a signed playback token.

    secret  The value of OPENDRM_TOKEN_SECRET on the opendrm server.
    user    Your viewer's account id. opendrm counts streams per user.
    title   The title id the viewer may play, as used in ``opendrm keys create -title``.
    claims  Anything your policies check, e.g. {"plan": "paid"}.
    device  A stable id for this device or app install. Streams are counted per
            device, so the same phone renewing its license never counts twice.
    ttl     Seconds the token is valid. Keep it short; players fetch a new one per play.
    """
    if not secret:
        raise ValueError("secret is empty")
    if not title:
        raise ValueError("title is empty")
    if user is None or str(user) == "":
        raise ValueError("user is empty")
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    extra = dict(claims or {})
    clash = RESERVED_CLAIMS.intersection(extra)
    if clash:
        raise ValueError(f"pass {sorted(clash)} as arguments, not in claims")

    issued = int(now if now is not None else time.time())
    payload: dict[str, Any] = {**extra, "sub": str(user), "title": title, "iat": issued, "exp": issued + ttl}
    if device:
        payload["device"] = device

    key = secret.encode() if isinstance(secret, str) else secret
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{header}.{body}".encode("ascii")
    signature = _b64(hmac.new(key, signing_input, hashlib.sha256).digest())
    return f"{header}.{body}.{signature}"
