import socket
import ssl
import sys
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urlparse

import tldextract
import whois

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


def print_section(data: dict) -> None:
    for kunci, nilai in data.items():
        print(f"{kunci:9} : {nilai}")


def main() -> None:
    if len(sys.argv) != 2:
        print("Pemakaian: uv run checker.py <url>")
        sys.exit(1)

    raw_url = sys.argv[1]
    hasil = parse_url(raw_url)
    print_section(hasil)

    if not hasil["host"]:
        print("URL tidak valid: host kosong")
        sys.exit(1)

    print("\n[SSL]")
    print_section(check_ssl(hasil["host"], hasil["port"] or 443))

    print("\n[UMUR DOMAIN]")
    print_section(check_domain_age(hasil["host"]))

    print("\n[TANDA MENCURIGAKAN]")
    flags = check_suspicious(raw_url, hasil["host"])
    if flags:
        for f in flags:
            print(f"- {f}")
    else:
        print("tidak ada tanda mencurigakan")


if __name__ == "__main__":
    main()
