"""
Test infrastructure for the Quesen SDK.

Sync tests need a real HTTP server because httpx.ASGITransport is async-only.
We spin up uvicorn in a background thread on a session-scoped fixture and
tear it down at the end. Each test that needs a specific env configuration
must run the server itself; see the `live_server` factory fixture below.
"""

from __future__ import annotations

import contextlib
import importlib
import os
import socket
import sys
import threading
import time
from typing import Callable

import pytest
import uvicorn

# Make the parent Quesen package importable from within sdks/python/tests.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _reload_app(env: dict | None = None):
    for k in list(os.environ):
        if k.startswith("QUESEN_"):
            del os.environ[k]
    if env:
        os.environ.update(env)
    try:
        from quesen import keys, telegram, reports  # noqa: F401
        from quesen import api as api_module
    except ImportError:
        # The sovereign engine package `quesen` lives in the private monorepo
        # (Quesen-sib), not in this split-out SDK repo. Engine-dependent
        # integration tests skip cleanly here; unit tests (client wiring, tsc
        # builders, receipt verification) still run standalone.
        pytest.skip("engine package 'quesen' not available in standalone SDK repo")
    importlib.reload(keys)
    importlib.reload(telegram)
    importlib.reload(reports)
    importlib.reload(api_module)
    return api_module.app


class _BackgroundServer:
    def __init__(self, app, host: str, port: int) -> None:
        self.host = host
        self.port = port
        cfg = uvicorn.Config(app, host=host, port=port, log_level="warning", access_log=False)
        self.server = uvicorn.Server(cfg)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> None:
        self.thread.start()
        # Wait for readiness.
        deadline = time.time() + 10.0
        while time.time() < deadline:
            with contextlib.suppress(Exception):
                s = socket.create_connection((self.host, self.port), timeout=0.5)
                s.close()
                return
            time.sleep(0.05)
        raise RuntimeError(f"uvicorn did not start within 10s on {self.host}:{self.port}")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture
def live_server() -> Callable[[dict | None], _BackgroundServer]:
    """
    Factory fixture: `srv = live_server(env)` boots a fresh uvicorn on a free
    port with the supplied env. Cleanup happens via the fixture finalizer.
    """
    servers: list[_BackgroundServer] = []

    def _factory(env: dict | None = None) -> _BackgroundServer:
        app = _reload_app(env)
        srv = _BackgroundServer(app, "127.0.0.1", _free_port())
        srv.start()
        servers.append(srv)
        return srv

    yield _factory

    for s in servers:
        s.stop()
