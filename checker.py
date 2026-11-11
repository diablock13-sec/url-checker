import sys
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


def main() -> None:
    if len(sys.argv) != 2:
        print("Pemakaian: uv run checker.py <url>")
        sys.exit(1)
    hasil = parse_url(sys.argv[1])
    for kunci, nilai in hasil.items():
        print(f"{kunci:8} : {nilai}")


if __name__ == "__main__":
    main()
