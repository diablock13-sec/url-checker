import argparse
import base64
import contextlib
import hashlib
import json
import math
import os
import socket
import ssl
import sys
import time
from datetime import UTC, datetime
from difflib import SequenceMatcher
from importlib import metadata
from pathlib import Path
from urllib.parse import urlparse

import requests
import tldextract
import whois
from dotenv import load_dotenv

from url_checker.config import Config, ConfigError, default_config, load_config

load_dotenv()

VT_BASE = "https://www.virustotal.com/api/v3"
RATE_LIMIT_WAIT_DEFAULT = 15.0  # detik, kalau Retry-After tidak ada atau tidak terbaca
RATE_LIMIT_WAIT_MAX = 30.0  # detik, batas atas menunggu setelah 429
VT_CACHE_TTL = 6 * 3600  # detik. Pendek, karena situs bisa berubah jadi berbahaya
VT_CACHE_MAX = 500  # jumlah entri maksimal di cache

# angka yang sering dipakai menyamar jadi huruf
LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})


def parse_url(url: str) -> dict:
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    return {
        "scheme": p.scheme,
        "host": p.hostname,
        "port": p.port,
        "path": p.path,
        "query": p.query,
    }


def short_error(e: Exception) -> str:
    text = str(e).strip()
    return text.splitlines()[0] if text else type(e).__name__


def check_ssl(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, port), timeout=5) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as s,
        ):
            cert = s.getpeercert()
    except (ssl.SSLError, OSError) as e:
        return {"ok": False, "error": short_error(e)}

    expires = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=UTC
    )
    days_left = (expires - datetime.now(UTC)).days
    issuer = dict(item[0] for item in cert["issuer"])
    return {
        "ok": True,
        "issuer": issuer.get("organizationName", "?"),
        "expires": expires.date().isoformat(),
        "days_left": days_left,
    }


def check_domain_age(host: str) -> dict:
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return {"ok": False, "error": "domain tidak dikenali"}
    domain = f"{ext.domain}.{ext.suffix}"

    try:
        data = whois.whois(domain)
    except Exception as e:  # noqa: BLE001 (python-whois melempar banyak jenis error)
        msg = short_error(e)
        if "No match" in msg:
            msg = "domain tidak terdaftar"
        return {"ok": False, "error": msg}

    created = data.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if not isinstance(created, datetime):
        return {"ok": False, "error": "tanggal pembuatan tidak ada di WHOIS"}
    if created.tzinfo is None:
        created = created.replace(tzinfo=UTC)

    age_days = (datetime.now(UTC) - created).days
    result = {
        "ok": True,
        "domain": domain,
        "created": created.date().isoformat(),
        "age_days": age_days,
    }
    if age_days < 30:
        result["note"] = "domain sangat baru, lebih mencurigakan"
    return result


def check_suspicious(
    raw_url: str, host: str, config: Config | None = None
) -> list[str]:
    cfg = config or default_config()
    limits = cfg.limits
    flags = []

    # 1. '@' dicek di teks asli, karena urlparse membuangnya dari host
    if "@" in raw_url.split("?")[0]:
        flags.append("ada '@' di URL, tujuan sebenarnya bisa berbeda")

    ext = tldextract.extract(host)

    # 2. terlalu banyak subdomain
    subs = [s for s in ext.subdomain.split(".") if s]
    if len(subs) >= limits["many_subdomains"]:
        flags.append(f"subdomain terlalu banyak ({len(subs)})")

    # 3. tanda '-' berlebihan
    if host.count("-") >= limits["many_hyphens"]:
        flags.append(f"tanda '-' berlebihan ({host.count('-')})")

    # 4. mirip atau memuat nama merek
    registered = f"{ext.domain}.{ext.suffix}"
    label = ext.domain.translate(LOOKALIKE)
    for brand, real_domains in cfg.brands.items():
        if registered in real_domains:
            continue
        if brand in label:
            flags.append(f"memuat nama merek '{brand}' tapi bukan domain resminya")
        elif SequenceMatcher(None, label, brand).ratio() >= limits["brand_similarity"]:
            flags.append(f"mirip nama merek '{brand}'")

    return flags


def vt_stats(stats: dict) -> dict:
    return {
        "ok": True,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


class VTRateLimited(Exception):
    """VirusTotal menjawab 429 lagi setelah satu kali mencoba ulang."""


def _now() -> float:
    return time.time()


def _cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "url-checker" / "virustotal.json"


def _cache_key(url: str) -> str:
    # hash, supaya URL yang diperiksa tidak tersimpan sebagai teks di disk
    return hashlib.sha256(url.encode()).hexdigest()


def _is_number(x: object) -> bool:
    return type(x) in (int, float)


def _cache_load() -> dict:
    try:
        data = json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _cache_get(url: str) -> dict | None:
    entry = _cache_load().get(_cache_key(url))
    if not isinstance(entry, dict):
        return None
    saved, stats = entry.get("time"), entry.get("stats")
    if not _is_number(saved) or not isinstance(stats, dict):
        return None
    if not all(type(v) is int for v in stats.values()):
        return None
    age = _now() - saved
    if not 0 <= age <= VT_CACHE_TTL:
        return None
    result = vt_stats(stats)
    result["cached"] = True
    result["age_minutes"] = int(age // 60)
    return result


def _cache_put(url: str, stats: dict) -> None:
    now = _now()
    data = {
        k: v
        for k, v in _cache_load().items()
        if isinstance(v, dict)
        and _is_number(v.get("time"))
        and 0 <= now - v["time"] <= VT_CACHE_TTL
    }
    data[_cache_key(url)] = {"time": now, "stats": stats}
    excess = max(0, len(data) - VT_CACHE_MAX)
    for name in sorted(data, key=lambda n: data[n]["time"])[:excess]:
        del data[name]
    path = _cache_path()
    # cache gagal ditulis bukan alasan menggagalkan analisis
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, path)


def _retry_wait(r: requests.Response) -> float:
    try:
        wait = float(r.headers.get("Retry-After", ""))
    except ValueError:  # kosong, atau format tanggal HTTP
        return RATE_LIMIT_WAIT_DEFAULT
    if math.isnan(wait):
        return RATE_LIMIT_WAIT_DEFAULT
    return min(max(wait, 1.0), RATE_LIMIT_WAIT_MAX)


def _vt_send(method: str, url: str, **kwargs) -> requests.Response:
    """Kirim request ke VirusTotal. Kena 429: tunggu sekali lalu coba lagi."""
    for attempt in (1, 2):
        r = requests.request(method, url, timeout=15, **kwargs)
        if r.status_code != 429:
            return r
        if attempt == 1:
            time.sleep(_retry_wait(r))
    raise VTRateLimited


def _query_virustotal(url: str, key: str) -> dict:
    headers = {"x-apikey": key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        r = _vt_send("GET", f"{VT_BASE}/urls/{url_id}", headers=headers)

        if r.status_code == 404:
            # belum pernah discan: kirim, lalu tunggu hasilnya
            r = _vt_send("POST", f"{VT_BASE}/urls", headers=headers, data={"url": url})
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]
            for _ in range(4):
                time.sleep(5)  # jeda, juga menjaga batas 4 request/menit
                a = _vt_send(
                    "GET", f"{VT_BASE}/analyses/{analysis_id}", headers=headers
                )
                a.raise_for_status()
                attrs = a.json()["data"]["attributes"]
                if attrs["status"] == "completed":
                    return vt_stats(attrs["stats"])
            return {"ok": False, "error": "analisis belum selesai, coba lagi nanti"}

        r.raise_for_status()
        return vt_stats(r.json()["data"]["attributes"]["last_analysis_stats"])
    except VTRateLimited:
        return {
            "ok": False,
            "error": "VirusTotal kena batas (429), coba lagi nanti",
            "rate_limited": True,
        }
    except requests.RequestException as e:
        return {"ok": False, "error": short_error(e)}
    except (KeyError, TypeError, ValueError):
        return {"ok": False, "error": "respons VirusTotal tidak terduga"}


def check_virustotal(url: str) -> dict:
    key = os.getenv("VT_API_KEY")
    if not key:
        return {"ok": False, "error": "VT_API_KEY belum diatur di .env"}

    cached = _cache_get(url)
    if cached:
        return cached

    result = _query_virustotal(url, key)
    if result.get("ok"):  # hanya hasil sukses yang disimpan
        _cache_put(url, {k: v for k, v in result.items() if k != "ok"})
    return result


def score(
    ssl_info: dict,
    age_info: dict,
    flags: list[str],
    vt_info: dict,
    config: Config | None = None,
) -> tuple[str, int, list[str]]:
    cfg = config or default_config()
    w, lim = cfg.weights, cfg.limits
    points = 0
    reasons = []

    if vt_info.get("ok"):
        mal = vt_info["malicious"]
        sus = vt_info["suspicious"]
        if mal >= lim["vt_malicious_high_count"]:
            points += w["vt_malicious_high"]
            reasons.append(
                f"{mal} mesin VirusTotal menandai berbahaya (+{w['vt_malicious_high']})"
            )
        elif mal >= 1:
            points += w["vt_malicious_low"]
            reasons.append(
                f"{mal} mesin VirusTotal menandai berbahaya (+{w['vt_malicious_low']})"
            )
        if sus >= 1:
            points += w["vt_suspicious"]
            reasons.append(
                f"{sus} mesin VirusTotal menandai curiga (+{w['vt_suspicious']})"
            )
    else:
        reasons.append("VirusTotal tidak tersedia, penilaian kurang akurat (+0)")

    if age_info.get("ok"):
        age = age_info["age_days"]
        if age < lim["domain_new_days"]:
            points += w["domain_new"]
            reasons.append(f"domain berumur {age} hari (+{w['domain_new']})")
        elif age < lim["domain_young_days"]:
            points += w["domain_young"]
            reasons.append(f"domain berumur {age} hari (+{w['domain_young']})")

    if not ssl_info.get("ok"):
        points += w["ssl_failed"]
        reasons.append(f"SSL gagal diperiksa (+{w['ssl_failed']})")
    elif ssl_info["days_left"] < lim["ssl_expiring_days"]:
        points += w["ssl_expiring"]
        reasons.append(
            f"sertifikat SSL tinggal {ssl_info['days_left']} hari (+{w['ssl_expiring']})"
        )

    for f in flags:
        points += w["flag"]
        reasons.append(f"{f} (+{w['flag']})")

    if points >= cfg.thresholds["bahaya"]:
        verdict = "BAHAYA"
    elif points >= cfg.thresholds["curiga"]:
        verdict = "CURIGA"
    else:
        verdict = "AMAN"
    return verdict, points, reasons


NOTE = "AMAN bukan jaminan, ini hanya sinyal sederhana"

# Kode keluar. Argparse bawaan memakai 2 untuk salah pakai, bentrok dengan BAHAYA,
# jadi salah pakai dan URL tidak valid memakai 64 (EX_USAGE).
EXIT_CODES = {"AMAN": 0, "CURIGA": 1, "BAHAYA": 2}
EXIT_USAGE = 64


class InvalidURLError(ValueError):
    """URL tidak bisa diperiksa."""


def analyze(raw_url: str, config: Config | None = None) -> dict:
    """Jalankan semua pemeriksaan dan kembalikan hasilnya. Tidak mencetak apa pun."""
    url_info = parse_url(raw_url)
    if not url_info["host"]:
        raise InvalidURLError("URL tidak valid: host kosong")
    full_url = raw_url if "://" in raw_url else "https://" + raw_url

    ssl_info = check_ssl(url_info["host"], url_info["port"] or 443)
    age_info = check_domain_age(url_info["host"])
    flags = check_suspicious(raw_url, url_info["host"], config)
    vt_info = check_virustotal(full_url)
    verdict, points, reasons = score(ssl_info, age_info, flags, vt_info, config)
    return {
        "url": url_info,
        "ssl": ssl_info,
        "domain_age": age_info,
        "flags": flags,
        "virustotal": vt_info,
        "verdict": verdict,
        "score": points,
        "reasons": reasons,
        "note": NOTE,
    }


def print_section(data: dict) -> None:
    for kunci, nilai in data.items():
        print(f"{kunci:10} : {nilai}")


def render_text(result: dict) -> None:
    print_section(result["url"])
    print("\n[SSL]")
    print_section(result["ssl"])
    print("\n[UMUR DOMAIN]")
    print_section(result["domain_age"])
    print("\n[TANDA MENCURIGAKAN]")
    if result["flags"]:
        for f in result["flags"]:
            print(f"- {f}")
    else:
        print("tidak ada tanda mencurigakan")
    print("\n[VIRUSTOTAL]")
    print_section(result["virustotal"])
    print("\n[PENILAIAN]")
    print(f"hasil      : {result['verdict']} (skor {result['score']})")
    for r in result["reasons"]:
        print(f"- {r}")
    print(f"catatan    : {result['note']}")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="url-checker",
        description="Periksa sinyal keamanan sebuah URL.",
        epilog="Kode keluar: 0 AMAN, 1 CURIGA, 2 BAHAYA, 64 salah pakai atau URL tidak valid.",
    )
    parser.add_argument("url", help="URL atau domain yang diperiksa")
    parser.add_argument("--json", action="store_true", help="keluaran JSON, bukan teks")
    parser.add_argument(
        "--config", metavar="FILE", help="file konfigurasi TOML (bawaan: config.toml paket)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {metadata.version('url-checker')}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config) if args.config else default_config()
        result = analyze(args.url, config)
    except (ConfigError, InvalidURLError) as e:
        print(e, file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        render_text(result)
    return EXIT_CODES[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
