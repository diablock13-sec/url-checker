import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Test tidak boleh menyentuh jaringan. Upaya koneksi langsung menggagalkan test."""

    def boom(*args, **kwargs):
        raise AssertionError("test mencoba memakai jaringan")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch, tmp_path):
    """Cache VirusTotal selalu di folder sementara, bukan ~/.cache asli."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
