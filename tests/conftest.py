import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Test tidak boleh menyentuh jaringan. Upaya koneksi langsung menggagalkan test."""

    def boom(*args, **kwargs):
        raise AssertionError("test mencoba memakai jaringan")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
