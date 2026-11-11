import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import tldextract
import whois


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


def check_ssl(host: str, port: int = 443) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
    except (ssl.SSLError, OSError) as e:
        return {"ok": False, "error": str(e)}

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
        return {"ok": False, "error": str(e)}

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


def print_section(data: dict) -> None:
    for kunci, nilai in data.items():
        print(f"{kunci:9} : {nilai}")


def main() -> None:
    if len(sys.argv) != 2:
        print("Pemakaian: uv run checker.py <url>")
        sys.exit(1)

    hasil = parse_url(sys.argv[1])
    print_section(hasil)

    if not hasil["host"]:
        print("URL tidak valid: host kosong")
        sys.exit(1)

    print("\n[SSL]")
    print_section(check_ssl(hasil["host"], hasil["port"] or 443))

    print("\n[UMUR DOMAIN]")
    print_section(check_domain_age(hasil["host"]))


if __name__ == "__main__":
    main()
