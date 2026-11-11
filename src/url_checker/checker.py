import base64
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from difflib import SequenceMatcher
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
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
    except (ssl.SSLError, OSError) as e:
        return {"ok": False, "error": short_error(e)}

    expires = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
    )
    days_left = (expires - datetime.now(timezone.utc)).days
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
    except Exception as e:
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
        created = created.replace(tzinfo=timezone.utc)

    age_days = (datetime.now(timezone.utc) - created).days
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


def print_section(data: dict) -> None:
    for kunci, nilai in data.items():
        print(f"{kunci:10} : {nilai}")


def main() -> None:
    if len(sys.argv) != 2:
        print("Pemakaian: url-checker <url>")
        sys.exit(1)

    raw_url = sys.argv[1]
    full_url = raw_url if "://" in raw_url else "https://" + raw_url
    hasil = parse_url(raw_url)
    print_section(hasil)

    if not hasil["host"]:
        print("URL tidak valid: host kosong")
        sys.exit(1)

    print("\n[SSL]")
    ssl_info = check_ssl(hasil["host"], hasil["port"] or 443)
    print_section(ssl_info)

    print("\n[UMUR DOMAIN]")
    age_info = check_domain_age(hasil["host"])
    print_section(age_info)

    print("\n[TANDA MENCURIGAKAN]")
    flags = check_suspicious(raw_url, hasil["host"])
    if flags:
        for f in flags:
            print(f"- {f}")
    else:
        print("tidak ada tanda mencurigakan")

    print("\n[VIRUSTOTAL]")
    vt_info = check_virustotal(full_url)
    print_section(vt_info)

    verdict, points, reasons = score(ssl_info, age_info, flags, vt_info)
    print("\n[PENILAIAN]")
    print(f"hasil      : {verdict} (skor {points})")
    for r in reasons:
        print(f"- {r}")
    print("catatan    : AMAN bukan jaminan, ini hanya sinyal sederhana")


if __name__ == "__main__":
    main()
