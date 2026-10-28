"""JWT identities for agents.

Each agent gets a short-lived token whose `sub` names its principal in the
mesh policy. Only the launcher and the gateway hold the signing secret;
agents only ever see their own token.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt

ALGORITHM = "HS256"


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Principal:
    sub: str
    claims: dict[str, Any] = field(default_factory=dict, compare=False)


class TokenIssuer:
    def __init__(self, secret: str, issuer: str = "agentmesh", audience: str = "agentmesh-gateway"):
        if len(secret) < 32:
            raise ValueError("JWT secret must be at least 32 characters")
        self._secret = secret
        self.issuer = issuer
        self.audience = audience

    def mint(self, sub: str, ttl_seconds: int = 3600, **extra: Any) -> str:
        now = int(time.time())
        payload = {
            "sub": sub,
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": uuid.uuid4().hex,
            **extra,
        }
        return jwt.encode(payload, self._secret, algorithm=ALGORITHM)

    def verify(self, token: str) -> Principal:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[ALGORITHM],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["sub", "exp", "iat", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(str(exc)) from exc
        return Principal(sub=claims["sub"], claims=claims)


def bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise AuthError("missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthError("Authorization must be 'Bearer <token>'")
    return token.strip()
