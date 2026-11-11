import pytest
import tldextract

from url_checker import checker
from url_checker.config import (
    DEFAULT_CONFIG_PATH,
    ConfigError,
    default_config,
    load_config,
)

DEFAULT_TEXT = DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")
OK_SSL = {"ok": True, "issuer": "CA", "expires": "2030-01-01", "days_left": 365}
OK_AGE = {"ok": True, "domain": "example.com", "created": "1995-08-14", "age_days": 11412}
OK_VT = {"ok": True, "malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 30}


@pytest.fixture(autouse=True)
def offline_tld(monkeypatch):
    """tldextract memakai daftar sufiks bawaan paket, tanpa mengunduh apa pun."""
    offline = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    monkeypatch.setattr(checker.tldextract, "extract", offline)


def tweak(tmp_path, old, new):
    assert DEFAULT_TEXT.count(old) == 1, f"{old!r} harus muncul tepat sekali"
    f = tmp_path / "config.toml"
    f.write_text(DEFAULT_TEXT.replace(old, new), encoding="utf-8")
    return f


def stub_checks(monkeypatch, flags=()):
    monkeypatch.setattr(checker, "check_ssl", lambda host, port=443: OK_SSL)
    monkeypatch.setattr(checker, "check_domain_age", lambda host: OK_AGE)
    monkeypatch.setattr(
        checker, "check_suspicious", lambda raw, host, config=None: list(flags)
    )
    monkeypatch.setattr(checker, "check_virustotal", lambda url: OK_VT)


# ---- nilai bawaan harus sama dengan perilaku lama ----


def test_default_values_match_original_behaviour():
    cfg = default_config()
    assert cfg.thresholds == {"curiga": 2, "bahaya": 5}
    assert cfg.weights == {
        "vt_malicious_high": 5,
        "vt_malicious_low": 3,
        "vt_suspicious": 1,
        "domain_new": 3,
        "domain_young": 1,
        "ssl_failed": 1,
        "ssl_expiring": 1,
        "flag": 2,
    }
    assert cfg.limits == {
        "vt_malicious_high_count": 3,
        "domain_new_days": 30,
        "domain_young_days": 180,
        "ssl_expiring_days": 7,
        "many_subdomains": 3,
        "many_hyphens": 3,
        "brand_similarity": 0.85,
    }
    assert cfg.brands == {
        "paypal": {"paypal.com"},
        "google": {"google.com", "google.co.id"},
        "facebook": {"facebook.com"},
        "microsoft": {"microsoft.com"},
        "apple": {"apple.com"},
        "amazon": {"amazon.com"},
        "tokopedia": {"tokopedia.com"},
        "shopee": {"shopee.co.id", "shopee.com"},
    }


def test_default_config_is_cached():
    assert default_config() is default_config()


# ---- konfigurasi mengubah hasil ----


def test_custom_flag_weight_changes_verdict(tmp_path):
    cfg = load_config(tweak(tmp_path, "flag = 2", "flag = 10"))
    assert checker.score(OK_SSL, OK_AGE, ["x"], OK_VT)[0] == "CURIGA"
    assert checker.score(OK_SSL, OK_AGE, ["x"], OK_VT, cfg)[0] == "BAHAYA"


def test_custom_threshold_changes_verdict(tmp_path):
    cfg = load_config(tweak(tmp_path, "bahaya = 5", "bahaya = 20"))
    malicious = {**OK_VT, "malicious": 3}
    assert checker.score(OK_SSL, OK_AGE, [], malicious)[0] == "BAHAYA"
    assert checker.score(OK_SSL, OK_AGE, [], malicious, cfg)[0] == "CURIGA"


def test_reason_text_shows_configured_weight(tmp_path):
    cfg = load_config(tweak(tmp_path, "flag = 2", "flag = 4"))
    _, points, reasons = checker.score(OK_SSL, OK_AGE, ["x"], OK_VT, cfg)
    assert points == 4
    assert reasons == ["x (+4)"]


def test_custom_brand_is_detected(tmp_path):
    cfg = load_config(tweak(tmp_path, "[brands]\n", '[brands]\nacmebank = ["acmebank.com"]\n'))
    host = "acmebank-login.xyz"
    assert checker.check_suspicious(f"https://{host}", host) == []
    flags = checker.check_suspicious(f"https://{host}", host, cfg)
    assert any("acmebank" in f for f in flags)


def test_custom_subdomain_limit(tmp_path):
    host = "a.b.c.example.com"
    url = f"https://{host}"
    cfg = load_config(tweak(tmp_path, "many_subdomains = 3", "many_subdomains = 5"))
    assert any("subdomain" in f for f in checker.check_suspicious(url, host))
    assert checker.check_suspicious(url, host, cfg) == []


def test_lookalike_brand_flagged_by_default():
    flags = checker.check_suspicious("https://paypa1.com", "paypa1.com")
    assert any("paypal" in f for f in flags)


def test_official_brand_domain_not_flagged():
    host = "www.paypal.com"
    assert checker.check_suspicious(f"https://{host}", host) == []


# ---- validasi ----


@pytest.mark.parametrize(
    ("old", "new", "match"),
    [
        ("curiga = 2", "curiga = 9", "curiga tidak boleh"),
        ("flag = 2", "flag = -1", "antara"),
        ("flag = 2", "flag = 2.5", "bulat"),
        ("flag = 2", "flag = true", "angka"),
        ("flag = 2", 'flag = "dua"', "angka"),
        ("many_hyphens = 3", "many_hyphenz = 3", "tidak dikenal"),
        ("ssl_failed = 1", "", "wajib hilang"),
        ("brand_similarity = 0.85", "brand_similarity = 1.5", "antara"),
        ("domain_new_days = 30", "domain_new_days = 400", "domain_new_days"),
        ('paypal = ["paypal.com"]', "paypal = []", "tidak boleh kosong"),
        ('paypal = ["paypal.com"]', 'PayPal = ["paypal.com"]', "huruf kecil"),
        ('paypal = ["paypal.com"]', "paypal = [1]", "daftar domain"),
    ],
)
def test_invalid_config_is_rejected(tmp_path, old, new, match):
    with pytest.raises(ConfigError, match=match):
        load_config(tweak(tmp_path, old, new))


def test_unknown_section_rejected(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text(DEFAULT_TEXT + "\n[extra]\nx = 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="bagian tidak dikenal"):
        load_config(f)


def test_broken_toml_rejected(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text("[thresholds\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="TOML rusak"):
        load_config(f)


def test_missing_file_rejected(tmp_path):
    with pytest.raises(ConfigError, match="tidak bisa membaca"):
        load_config(tmp_path / "tidak-ada.toml")


# ---- lewat CLI ----


def test_main_uses_config_file(monkeypatch, tmp_path):
    stub_checks(monkeypatch, flags=["x"])
    assert checker.main(["example.com"]) == 1
    cfg_file = tweak(tmp_path, "flag = 2", "flag = 10")
    assert checker.main(["--config", str(cfg_file), "example.com"]) == 2


def test_main_bad_config_exits_64(monkeypatch, tmp_path, capsys):
    stub_checks(monkeypatch)
    bad = tmp_path / "bad.toml"
    bad.write_text("[thresholds\n", encoding="utf-8")
    assert checker.main(["--config", str(bad), "example.com"]) == checker.EXIT_USAGE
    captured = capsys.readouterr()
    assert "TOML rusak" in captured.err
    assert captured.out == ""


def test_main_missing_config_exits_64(monkeypatch, tmp_path, capsys):
    stub_checks(monkeypatch)
    missing = tmp_path / "nope.toml"
    assert checker.main(["--config", str(missing), "example.com"]) == checker.EXIT_USAGE
    assert "tidak bisa membaca" in capsys.readouterr().err


# ---- catatan "sangat baru" mengikuti domain_new_days ----


def test_new_domain_note_follows_config(monkeypatch, tmp_path):
    stub_checks(monkeypatch)
    age_60 = {**OK_AGE, "age_days": 60}
    monkeypatch.setattr(checker, "check_domain_age", lambda host: age_60)
    cfg = load_config(tweak(tmp_path, "domain_new_days = 30", "domain_new_days = 90"))

    result = checker.analyze("example.com", cfg)

    assert "sangat baru" in result["domain_age"]["note"]


def test_new_domain_note_absent_above_default_limit(monkeypatch):
    stub_checks(monkeypatch)
    age_60 = {**OK_AGE, "age_days": 60}
    monkeypatch.setattr(checker, "check_domain_age", lambda host: age_60)

    result = checker.analyze("example.com")

    assert "note" not in result["domain_age"]
