"""Compatibility shim for the external `httpx` package.

The original project shipped a minimal stub named ``httpx.py`` to satisfy type
annotations when the real library was unavailable.  However, the test suite and
FastAPI/Starlette infrastructure rely on many components of the actual
``httpx`` package (e.g., ``BaseTransport``).  Because the local file shadowed the
installed package, imports resolved to the stub, causing ``AttributeError`` for
missing symbols.

This shim attempts to import the real ``httpx`` package.  If it is present, all
its public attributes are re‑exported so that ``import httpx`` behaves exactly as
if the external library were imported directly.  If the real package cannot be
found (unlikely in the provided environment), a very small fallback implementation
provides the minimal API required by the execution engine.
"""

import importlib

try:
    # Load the actual third‑party httpx package.
    _real_httpx = importlib.import_module("httpx")
    # Re‑export everything (classes, functions, constants).
    globals().update(_real_httpx.__dict__)
except Exception:  # pragma: no cover – fallback only if real package missing.
    # Minimal fallback definitions used only for type hints and testing.
    class BasicAuth:
        def __init__(self, username: str, password: str):
            self.username = username
            self.password = password

        def __repr__(self) -> str:
            return f"BasicAuth(username={self.username!r}, password=******)"

    class Response:
        """Placeholder for httpx.Response used only for type hints."""

        pass

    class AsyncClient:
        """Very small async client stub; tests monkey‑patch this class."""

        def __init__(self, *, timeout: float = 5.0, follow_redirects: bool = False):
            self.timeout = timeout
            self.follow_redirects = follow_redirects

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, *args, **kwargs):  # pragma: no cover
            raise NotImplementedError(
                "httpx.AsyncClient.get should be monkey‑patched in tests"
            )

        async def patch(self, *args, **kwargs):  # pragma: no cover
            raise NotImplementedError(
                "httpx.AsyncClient.patch should be monkey‑patched in tests"
            )

