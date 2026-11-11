import tomllib
from dataclasses import dataclass
from functools import cache
from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).with_name("config.toml")


class ConfigError(ValueError):
    """Isi file konfigurasi tidak valid."""


# bagian -> kunci -> (tipe, minimum, maksimum)
SCHEMA = {
    "thresholds": {
        "curiga": (int, 1, 100),
        "bahaya": (int, 1, 100),
    },
    "weights": {
        "vt_malicious_high": (int, 0, 100),
        "vt_malicious_low": (int, 0, 100),
        "vt_suspicious": (int, 0, 100),
        "domain_new": (int, 0, 100),
        "domain_young": (int, 0, 100),
        "ssl_failed": (int, 0, 100),
        "ssl_expiring": (int, 0, 100),
        "flag": (int, 0, 100),
    },
    "limits": {
        "vt_malicious_high_count": (int, 1, 1000),
        "domain_new_days": (int, 1, 36500),
        "domain_young_days": (int, 1, 36500),
        "ssl_expiring_days": (int, 1, 3650),
        "many_subdomains": (int, 1, 50),
        "many_hyphens": (int, 1, 50),
        "brand_similarity": (float, 0.0, 1.0),
    },
}


@dataclass(frozen=True)
class Config:
    thresholds: dict[str, int]
    weights: dict[str, int]
    limits: dict[str, int | float]
    brands: dict[str, frozenset[str]]


def _number(section: str, key: str, value: object, kind: type, lo: float, hi: float):
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ConfigError(f"[{section}] {key}: harus berupa angka")
    if kind is int and not isinstance(value, int):
        raise ConfigError(f"[{section}] {key}: harus bilangan bulat")
    if not lo <= value <= hi:
        raise ConfigError(f"[{section}] {key}: harus antara {lo} dan {hi}")
    return kind(value)


def _section(data: dict, name: str) -> dict:
    schema = SCHEMA[name]
    raw = data.get(name)
    if not isinstance(raw, dict):
        raise ConfigError(f"bagian [{name}] tidak ada")
    unknown = set(raw) - set(schema)
    if unknown:
        raise ConfigError(f"[{name}]: kunci tidak dikenal: {sorted(unknown)}")
    missing = set(schema) - set(raw)
    if missing:
        raise ConfigError(f"[{name}]: kunci wajib hilang: {sorted(missing)}")
    return {key: _number(name, key, raw[key], *schema[key]) for key in schema}


def _brands(data: dict) -> dict[str, frozenset[str]]:
    raw = data.get("brands")
    if not isinstance(raw, dict):
        raise ConfigError("bagian [brands] tidak ada")
    brands = {}
    for name, domains in raw.items():
        if not name.strip() or name != name.lower():
            raise ConfigError(f"[brands] '{name}': nama merek harus huruf kecil")
        valid = isinstance(domains, list) and domains
        if not valid or not all(isinstance(d, str) and d.strip() for d in domains):
            raise ConfigError(
                f"[brands] {name}: harus daftar domain teks, tidak boleh kosong"
            )
        brands[name] = frozenset(d.strip().lower() for d in domains)
    return brands


def load_config(path: Path | str = DEFAULT_CONFIG_PATH) -> Config:
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"tidak bisa membaca {path} ({type(exc).__name__})") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"TOML rusak di {path}: {exc}") from exc

    unknown = set(data) - set(SCHEMA) - {"brands"}
    if unknown:
        raise ConfigError(f"bagian tidak dikenal: {sorted(unknown)}")

    thresholds = _section(data, "thresholds")
    weights = _section(data, "weights")
    limits = _section(data, "limits")
    if thresholds["curiga"] > thresholds["bahaya"]:
        raise ConfigError("[thresholds] curiga tidak boleh lebih besar dari bahaya")
    if limits["domain_new_days"] > limits["domain_young_days"]:
        raise ConfigError("[limits] domain_new_days tidak boleh melebihi domain_young_days")
    return Config(thresholds, weights, limits, _brands(data))


@cache
def default_config() -> Config:
    """Muat config.toml bawaan sekali saja."""
    return load_config()
