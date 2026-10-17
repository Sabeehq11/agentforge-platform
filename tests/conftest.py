"""Shared fixtures. Every test runs with sockets disabled, so nothing in P0 can reach a network."""

from __future__ import annotations

import socket
from typing import Any

import pytest


class SocketOpened(AssertionError):
    pass


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_a: Any, **_k: Any) -> Any:
        raise SocketOpened("a test tried to open a network socket")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
