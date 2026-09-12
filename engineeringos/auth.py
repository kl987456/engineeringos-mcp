"""OIDC/JWT bearer verification for the remote MCP deployment."""
from __future__ import annotations

import asyncio
import os
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from mcp.server.auth.provider import AccessToken


_ALLOWED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
_MAX_TOKEN_BYTES = 16 * 1024
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class OIDCVerifier:
    def __init__(self, issuer: str, audience: str, required_scopes: list[str], jwks_uri: str | None = None):
        issuer = issuer.rstrip("/")
        parsed = urlparse(issuer)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            raise ValueError("OIDC issuer must be an absolute HTTP(S) URL")
        if parsed.scheme != "https":
            if os.environ.get("ENGINEERINGOS_ALLOW_INSECURE_OIDC") != "1" or parsed.hostname not in _LOOPBACK_HOSTS:
                raise ValueError("OIDC issuer must use HTTPS; insecure OIDC is allowed only for explicit loopback development")
        if not audience.strip():
            raise ValueError("OIDC audience must not be empty")
        self.issuer = issuer
        self.audience = audience
        self.required_scopes = frozenset(required_scopes)
        self.jwks_uri = jwks_uri or f"{self.issuer}/.well-known/jwks.json"
        jwks_parsed = urlparse(self.jwks_uri)
        if jwks_parsed.scheme not in {"https", "http"} or not jwks_parsed.netloc:
            raise ValueError("OIDC JWKS URI must be an absolute HTTP(S) URL")
        if jwks_parsed.scheme != "https":
            if os.environ.get("ENGINEERINGOS_ALLOW_INSECURE_OIDC") != "1" or jwks_parsed.hostname not in _LOOPBACK_HOSTS:
                raise ValueError("OIDC JWKS URI must use HTTPS; insecure JWKS is allowed only for explicit loopback development")
        self._jwks = PyJWKClient(self.jwks_uri, cache_jwk_set=True, lifespan=300)

    def _decode(self, token: str, algorithm: str) -> dict:
        key = self._jwks.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            issuer=self.issuer,
            audience=self.audience,
            options={"require": ["exp", "iss", "sub"]},
        )

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            if not isinstance(token, str) or len(token.encode("utf-8", errors="ignore")) > _MAX_TOKEN_BYTES:
                return None
            header = jwt.get_unverified_header(token)
            algorithm = header.get("alg")
            if algorithm not in _ALLOWED_ALGORITHMS:
                return None

            # PyJWKClient performs network I/O on cache misses; keep it off the
            # event loop so one slow issuer cannot stall every MCP request.
            claims = await asyncio.to_thread(self._decode, token, algorithm)
            subject = claims.get("sub")
            if not isinstance(subject, str) or not subject:
                return None

            raw_scopes = claims.get("scope", "")
            if isinstance(raw_scopes, str):
                scopes = raw_scopes.split()
            elif isinstance(raw_scopes, list) and all(isinstance(scope, str) for scope in raw_scopes):
                scopes = raw_scopes
            else:
                return None
            if not self.required_scopes.issubset(scopes):
                return None

            audience_claim = claims.get("aud")
            if isinstance(audience_claim, list) and len(audience_claim) > 1 and not claims.get("azp"):
                return None
            client_id = claims.get("azp", subject)
            if not isinstance(client_id, str) or not client_id:
                return None
            expires_at = claims.get("exp")
            if not isinstance(expires_at, int):
                return None
            return AccessToken(
                token=token,
                client_id=client_id,
                subject=subject,
                scopes=scopes,
                expires_at=expires_at,
                resource=self.audience,
                claims=claims,
            )
        except Exception:
            # Authentication failures are deliberately indistinguishable to the
            # caller; detailed token errors must not become an oracle.
            return None


def auth_env() -> tuple[str, str, list[str]]:
    issuer = os.environ.get("ENGINEERINGOS_OIDC_ISSUER")
    audience = os.environ.get("ENGINEERINGOS_OIDC_AUDIENCE")
    if not issuer or not audience:
        raise RuntimeError("Set ENGINEERINGOS_OIDC_ISSUER and ENGINEERINGOS_OIDC_AUDIENCE for remote authentication.")
    scopes = os.environ.get("ENGINEERINGOS_OIDC_SCOPES", "engineering:read").split()
    if not scopes:
        raise RuntimeError("ENGINEERINGOS_OIDC_SCOPES must contain at least one required scope")
    return issuer, audience, scopes
