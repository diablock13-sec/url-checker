import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse


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


def main() -> None:
    if len(sys.argv) != 2:
        print("Pemakaian: uv run checker.py <url>")
        sys.exit(1)

    hasil = parse_url(sys.argv[1])
    for kunci, nilai in hasil.items():
        print(f"{kunci:8} : {nilai}")

    if not hasil["host"]:
        print("URL tidak valid: host kosong")
        sys.exit(1)

    print()
    info = check_ssl(hasil["host"], hasil["port"] or 443)
    for kunci, nilai in info.items():
        print(f"{kunci:8} : {nilai}")


if __name__ == "__main__":
    main()
