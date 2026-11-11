import json
from types import SimpleNamespace

import pytest
import requests

from url_checker import checker

URL = "https://example.com"
STATS = {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 30}


class FakeResponse:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code = status
        self._body = body if body is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


def report(stats=STATS):
    return FakeResponse(200, {"data": {"attributes": {"last_analysis_stats": stats}}})


def analysis(status, stats=None):
    attrs = {"status": status}
    if stats is not None:
        attrs["stats"] = stats
    return FakeResponse(200, {"data": {"attributes": attrs}})


@pytest.fixture
def vt(monkeypatch):
    """Ganti requests.request dengan antrean respons palsu dan catat semua panggilan."""
    monkeypatch.setenv("VT_API_KEY", "kunci-palsu")
    box = SimpleNamespace(calls=[], queue=[], slept=[])
    monkeypatch.setattr(checker.time, "sleep", box.slept.append)

    def fake_request(method, url, **kwargs):
        box.calls.append((method, url))
        return box.queue.pop(0)  # antrean habis = ada request yang tidak diharapkan

    monkeypatch.setattr(checker.requests, "request", fake_request)
    return box


def test_no_key_makes_no_request(monkeypatch, vt):
    monkeypatch.delenv("VT_API_KEY")
    result = checker.check_virustotal(URL)
    assert result["ok"] is False
    assert vt.calls == []


def test_known_url_report(vt):
    vt.queue = [report()]
    assert checker.check_virustotal(URL) == {"ok": True, **STATS}
    assert len(vt.calls) == 1


def test_unknown_url_is_submitted_then_polled(vt):
    vt.queue = [
        FakeResponse(404),
        FakeResponse(200, {"data": {"id": "analysis-1"}}),
        analysis("queued"),
        analysis("completed", STATS),
    ]
    assert checker.check_virustotal(URL) == {"ok": True, **STATS}
    assert [m for m, _ in vt.calls] == ["GET", "POST", "GET", "GET"]
    assert vt.slept == [5, 5]


def test_analysis_never_completes(vt):
    vt.queue = [FakeResponse(404), FakeResponse(200, {"data": {"id": "a"}})]
    vt.queue += [analysis("queued") for _ in range(4)]
    result = checker.check_virustotal(URL)
    assert result["ok"] is False
    assert "belum selesai" in result["error"]


def test_unexpected_response_shape(vt):
    vt.queue = [FakeResponse(200, {"oops": 1})]
    result = checker.check_virustotal(URL)
    assert result["ok"] is False
    assert "tidak terduga" in result["error"]


# ---- cache ----


def test_second_call_uses_cache(vt):
    vt.queue = [report()]
    first = checker.check_virustotal(URL)
    second = checker.check_virustotal(URL)
    assert len(vt.calls) == 1
    assert "cached" not in first
    assert second["cached"] is True
    assert second["malicious"] == 2


def test_cache_expires(monkeypatch, vt):
    now = [1_000_000.0]
    monkeypatch.setattr(checker, "_now", lambda: now[0])
    vt.queue = [report(), report()]
    checker.check_virustotal(URL)
    now[0] += checker.VT_CACHE_TTL + 1
    result = checker.check_virustotal(URL)
    assert len(vt.calls) == 2
    assert "cached" not in result


def test_cache_reports_age(monkeypatch, vt):
    now = [1_000_000.0]
    monkeypatch.setattr(checker, "_now", lambda: now[0])
    vt.queue = [report()]
    checker.check_virustotal(URL)
    now[0] += 600
    assert checker.check_virustotal(URL)["age_minutes"] == 10


def test_failures_are_not_cached(vt):
    vt.queue = [FakeResponse(500), report()]
    assert checker.check_virustotal(URL)["ok"] is False
    assert checker.check_virustotal(URL)["ok"] is True
    assert len(vt.calls) == 2


def test_corrupt_cache_is_ignored_and_replaced(vt):
    path = checker._cache_path()
    path.parent.mkdir(parents=True)
    path.write_text("bukan json")
    vt.queue = [report()]
    assert checker.check_virustotal(URL)["ok"] is True
    assert json.loads(path.read_text())


def test_tampered_cache_entry_is_ignored(vt):
    path = checker._cache_path()
    path.parent.mkdir(parents=True)
    bad = {checker._cache_key(URL): {"time": checker._now(), "stats": {"malicious": "x"}}}
    path.write_text(json.dumps(bad))
    vt.queue = [report()]
    assert checker.check_virustotal(URL)["malicious"] == 2
    assert len(vt.calls) == 1


def test_cache_file_is_private(vt):
    vt.queue = [report()]
    checker.check_virustotal(URL)
    assert checker._cache_path().stat().st_mode & 0o777 == 0o600


def test_cache_does_not_store_plain_url(vt):
    vt.queue = [report()]
    checker.check_virustotal(URL)
    assert "example.com" not in checker._cache_path().read_text()


def test_cache_size_is_bounded(monkeypatch, vt):
    monkeypatch.setattr(checker, "VT_CACHE_MAX", 3)
    now = [1_000_000.0]
    monkeypatch.setattr(checker, "_now", lambda: now[0])
    for i in range(6):
        vt.queue = [report()]
        checker.check_virustotal(f"https://site{i}.example")
        now[0] += 1
    assert len(json.loads(checker._cache_path().read_text())) == 3


def test_unwritable_cache_does_not_break_analysis(monkeypatch, vt):
    def boom(*args, **kwargs):
        raise OSError("disk penuh")

    monkeypatch.setattr(checker.os, "open", boom)
    vt.queue = [report()]
    assert checker.check_virustotal(URL)["ok"] is True


# ---- kode 429 ----


def test_429_retries_once_after_retry_after(vt):
    vt.queue = [FakeResponse(429, headers={"Retry-After": "7"}), report()]
    assert checker.check_virustotal(URL)["ok"] is True
    assert vt.slept == [7.0]
    assert len(vt.calls) == 2


def test_429_wait_is_capped(vt):
    vt.queue = [FakeResponse(429, headers={"Retry-After": "9999"}), report()]
    checker.check_virustotal(URL)
    assert vt.slept == [checker.RATE_LIMIT_WAIT_MAX]


@pytest.mark.parametrize("header", [None, "", "besok", "nan"])
def test_429_unreadable_retry_after_uses_default(vt, header):
    headers = {} if header is None else {"Retry-After": header}
    vt.queue = [FakeResponse(429, headers=headers), report()]
    checker.check_virustotal(URL)
    assert vt.slept == [checker.RATE_LIMIT_WAIT_DEFAULT]


def test_429_twice_reports_rate_limited(vt):
    vt.queue = [FakeResponse(429), FakeResponse(429)]
    result = checker.check_virustotal(URL)
    assert result["ok"] is False
    assert result["rate_limited"] is True
    assert "429" in result["error"]
    assert len(vt.calls) == 2


def test_rate_limited_result_is_not_cached(vt):
    vt.queue = [FakeResponse(429), FakeResponse(429), report()]
    assert checker.check_virustotal(URL)["ok"] is False
    assert checker.check_virustotal(URL)["ok"] is True
