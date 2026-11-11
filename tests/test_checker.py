import json

import pytest

from url_checker import checker

OK_SSL = {"ok": True, "issuer": "CA", "expires": "2030-01-01", "days_left": 365}
OK_AGE = {
    "ok": True,
    "domain": "example.com",
    "created": "1995-08-14",
    "age_days": 11412,
}
OK_VT = {"ok": True, "malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 30}


def vt(mal=0, sus=0):
    return {**OK_VT, "malicious": mal, "suspicious": sus}


def run_score(**override):
    args = {"ssl_info": OK_SSL, "age_info": OK_AGE, "flags": [], "vt_info": OK_VT}
    args.update(override)
    return checker.score(**args)


def patch_checks(
    monkeypatch, *, ssl=OK_SSL, age=OK_AGE, flags=(), vt_info=OK_VT, seen=None
):
    def fake_vt(url):
        if seen is not None:
            seen["vt_url"] = url
        return vt_info

    monkeypatch.setattr(checker, "check_ssl", lambda host, port=443: ssl)
    monkeypatch.setattr(checker, "check_domain_age", lambda host: age)
    monkeypatch.setattr(checker, "check_suspicious", lambda raw, host, config=None: list(flags))
    monkeypatch.setattr(checker, "check_virustotal", fake_vt)


# ---- score ----


def test_clean_is_safe():
    verdict, points, reasons = run_score()
    assert (verdict, points, reasons) == ("AMAN", 0, [])


@pytest.mark.parametrize(
    ("mal", "sus", "expected"),
    [(0, 0, 0), (1, 0, 3), (2, 0, 3), (3, 0, 5), (0, 1, 1), (1, 1, 4), (3, 2, 6)],
)
def test_virustotal_points(mal, sus, expected):
    assert run_score(vt_info=vt(mal, sus))[1] == expected


@pytest.mark.parametrize(
    ("age_days", "expected"), [(0, 3), (29, 3), (30, 1), (179, 1), (180, 0)]
)
def test_domain_age_boundaries(age_days, expected):
    age = {**OK_AGE, "age_days": age_days}
    assert run_score(age_info=age)[1] == expected


@pytest.mark.parametrize(("days_left", "expected"), [(0, 1), (6, 1), (7, 0)])
def test_ssl_expiry_boundaries(days_left, expected):
    ssl = {**OK_SSL, "days_left": days_left}
    assert run_score(ssl_info=ssl)[1] == expected


def test_ssl_failure_adds_point():
    assert run_score(ssl_info={"ok": False, "error": "x"})[1] == 1


def test_each_flag_adds_two_points():
    assert run_score(flags=["a", "b"])[1] == 4


@pytest.mark.parametrize(
    ("flags", "sus", "verdict"),
    [
        ([], 1, "AMAN"),
        (["a"], 0, "CURIGA"),
        (["a", "b"], 0, "CURIGA"),
        (["a", "b"], 1, "BAHAYA"),
    ],
)
def test_verdict_thresholds(flags, sus, verdict):
    assert run_score(flags=flags, vt_info=vt(sus=sus))[0] == verdict


def test_virustotal_unavailable_adds_no_points_but_says_so():
    _, points, reasons = run_score(vt_info={"ok": False, "error": "x"})
    assert points == 0
    assert any("VirusTotal tidak tersedia" in r for r in reasons)


def test_age_unavailable_adds_no_points():
    assert run_score(age_info={"ok": False, "error": "x"})[1] == 0


# ---- analyze ----


def test_analyze_result_shape(monkeypatch):
    patch_checks(monkeypatch)
    result = checker.analyze("example.com")
    assert set(result) == {
        "url",
        "ssl",
        "domain_age",
        "flags",
        "virustotal",
        "verdict",
        "score",
        "reasons",
        "note",
    }
    assert result["verdict"] == "AMAN"
    assert result["url"]["host"] == "example.com"


def test_analyze_adds_https_for_virustotal(monkeypatch):
    seen = {}
    patch_checks(monkeypatch, seen=seen)
    checker.analyze("example.com")
    assert seen["vt_url"] == "https://example.com"


def test_analyze_keeps_given_scheme_for_virustotal(monkeypatch):
    seen = {}
    patch_checks(monkeypatch, seen=seen)
    checker.analyze("http://example.com/x")
    assert seen["vt_url"] == "http://example.com/x"


def test_analyze_empty_host_raises(monkeypatch):
    patch_checks(monkeypatch)
    with pytest.raises(checker.InvalidURLError):
        checker.analyze("http://")


# ---- main: keluaran dan kode keluar ----


@pytest.mark.parametrize(
    ("flags", "vt_info", "code", "verdict"),
    [
        ([], vt(), 0, "AMAN"),
        (["x"], vt(), 1, "CURIGA"),
        ([], vt(mal=3), 2, "BAHAYA"),
    ],
)
def test_main_exit_codes(monkeypatch, capsys, flags, vt_info, code, verdict):
    patch_checks(monkeypatch, flags=flags, vt_info=vt_info)
    assert checker.main(["example.com"]) == code
    assert verdict in capsys.readouterr().out


def test_main_text_output_has_sections(monkeypatch, capsys):
    patch_checks(monkeypatch)
    checker.main(["example.com"])
    out = capsys.readouterr().out
    for section in ("[SSL]", "[UMUR DOMAIN]", "[VIRUSTOTAL]", "[PENILAIAN]"):
        assert section in out


def test_main_json_is_pure_json_on_stdout(monkeypatch, capsys):
    patch_checks(monkeypatch, flags=["x"])
    assert checker.main(["--json", "example.com"]) == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["verdict"] == "CURIGA"
    assert data["flags"] == ["x"]
    assert captured.err == ""


def test_main_invalid_url(monkeypatch, capsys):
    patch_checks(monkeypatch)
    assert checker.main(["http://"]) == checker.EXIT_USAGE
    captured = capsys.readouterr()
    assert "host kosong" in captured.err
    assert captured.out == ""


def test_main_without_arguments_exits_64():
    with pytest.raises(SystemExit) as info:
        checker.main([])
    assert info.value.code == 64


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as info:
        checker.main(["--version"])
    assert info.value.code == 0
    assert "url-checker" in capsys.readouterr().out
