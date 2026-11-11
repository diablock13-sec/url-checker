import argparse
import base64
import json
import os
import socket
import ssl
import sys
import time
from datetime import UTC, datetime
from difflib import SequenceMatcher
from importlib import metadata
from urllib.parse import urlparse

import requests
import tldextract
import whois
from dotenv import load_dotenv

load_dotenv()

VT_BASE = "https://www.virustotal.com/api/v3"

# merek -> domain resmi miliknya
BRANDS = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "google.co.id"},
    "facebook": {"facebook.com"},
    "microsoft": {"microsoft.com"},
    "apple": {"apple.com"},
    "amazon": {"amazon.com"},
    "tokopedia": {"tokopedia.com"},
    "shopee": {"shopee.co.id", "shopee.com"},
}

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


def check_suspicious(raw_url: str, host: str) -> list[str]:
    flags = []

    # 1. '@' dicek di teks asli, karena urlparse membuangnya dari host
    if "@" in raw_url.split("?")[0]:
        flags.append("ada '@' di URL, tujuan sebenarnya bisa berbeda")

    ext = tldextract.extract(host)

    # 2. terlalu banyak subdomain
    subs = [s for s in ext.subdomain.split(".") if s]
    if len(subs) >= 3:
        flags.append(f"subdomain terlalu banyak ({len(subs)})")

    # 3. tanda '-' berlebihan
    if host.count("-") >= 3:
        flags.append(f"tanda '-' berlebihan ({host.count('-')})")

    # 4. mirip atau memuat nama merek
    registered = f"{ext.domain}.{ext.suffix}"
    label = ext.domain.translate(LOOKALIKE)
    for brand, real_domains in BRANDS.items():
        if registered in real_domains:
            continue
        if brand in label:
            flags.append(f"memuat nama merek '{brand}' tapi bukan domain resminya")
        elif SequenceMatcher(None, label, brand).ratio() >= 0.85:
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


def check_virustotal(url: str) -> dict:
    key = os.getenv("VT_API_KEY")
    if not key:
        return {"ok": False, "error": "VT_API_KEY belum diatur di .env"}

    headers = {"x-apikey": key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    try:
        r = requests.get(f"{VT_BASE}/urls/{url_id}", headers=headers, timeout=15)

        if r.status_code == 404:
            # belum pernah discan: kirim, lalu tunggu hasilnya
            r = requests.post(
                f"{VT_BASE}/urls", headers=headers, data={"url": url}, timeout=15
            )
            r.raise_for_status()
            analysis_id = r.json()["data"]["id"]
            for _ in range(4):
                time.sleep(5)  # jeda, juga menjaga batas 4 request/menit
                a = requests.get(
                    f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15
                )
                a.raise_for_status()
                attrs = a.json()["data"]["attributes"]
                if attrs["status"] == "completed":
                    return vt_stats(attrs["stats"])
            return {"ok": False, "error": "analisis belum selesai, coba lagi nanti"}

        r.raise_for_status()
        return vt_stats(r.json()["data"]["attributes"]["last_analysis_stats"])
    except requests.RequestException as e:
        return {"ok": False, "error": short_error(e)}


def score(
    ssl_info: dict, age_info: dict, flags: list[str], vt_info: dict
) -> tuple[str, int, list[str]]:
    points = 0
    reasons = []

    if vt_info.get("ok"):
        mal = vt_info["malicious"]
        sus = vt_info["suspicious"]
        if mal >= 3:
            points += 5
            reasons.append(f"{mal} mesin VirusTotal menandai berbahaya (+5)")
        elif mal >= 1:
            points += 3
            reasons.append(f"{mal} mesin VirusTotal menandai berbahaya (+3)")
        if sus >= 1:
            points += 1
            reasons.append(f"{sus} mesin VirusTotal menandai curiga (+1)")
    else:
        reasons.append("VirusTotal tidak tersedia, penilaian kurang akurat (+0)")

    if age_info.get("ok"):
        age = age_info["age_days"]
        if age < 30:
            points += 3
            reasons.append(f"domain berumur {age} hari (+3)")
        elif age < 180:
            points += 1
            reasons.append(f"domain berumur {age} hari (+1)")

    if not ssl_info.get("ok"):
        points += 1
        reasons.append("SSL gagal diperiksa (+1)")
    elif ssl_info["days_left"] < 7:
        points += 1
        reasons.append(f"sertifikat SSL tinggal {ssl_info['days_left']} hari (+1)")

    for f in flags:
        points += 2
        reasons.append(f"{f} (+2)")

    if points >= 5:
        verdict = "BAHAYA"
    elif points >= 2:
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


def analyze(raw_url: str) -> dict:
    """Jalankan semua pemeriksaan dan kembalikan hasilnya. Tidak mencetak apa pun."""
    url_info = parse_url(raw_url)
    if not url_info["host"]:
        raise InvalidURLError("URL tidak valid: host kosong")
    full_url = raw_url if "://" in raw_url else "https://" + raw_url

    ssl_info = check_ssl(url_info["host"], url_info["port"] or 443)
    age_info = check_domain_age(url_info["host"])
    flags = check_suspicious(raw_url, url_info["host"])
    vt_info = check_virustotal(full_url)
    verdict, points, reasons = score(ssl_info, age_info, flags, vt_info)
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
        "--version",
        action="version",
        version=f"%(prog)s {metadata.version('url-checker')}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyze(args.url)
    except InvalidURLError as e:
        print(e, file=sys.stderr)
        return EXIT_USAGE
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        render_text(result)
    return EXIT_CODES[result["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
