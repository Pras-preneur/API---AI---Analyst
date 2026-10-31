"""Pytest session-level configuration for API-Security-Assistant.
Ensures mock API server on 127.0.0.1:8001 is available for integration tests.
"""

import time
import socket
import threading
import pytest
import uvicorn
from app.mock_api import mock_app


def _is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


@pytest.fixture(scope="session", autouse=True)
def ensure_mock_api_server():
    """Ensure mock target API is running on 127.0.0.1:8001 during pytest runs."""
    if _is_port_open("127.0.0.1", 8001):
        yield
        return

    config = uvicorn.Config(mock_app, host="127.0.0.1", port=8001, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait up to 3 seconds for server socket to accept connections
    for _ in range(30):
        if _is_port_open("127.0.0.1", 8001):
            break
        time.sleep(0.1)

    yield

    server.should_exit = True

