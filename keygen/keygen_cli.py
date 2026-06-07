"""
CLI tool for generating license keys
Usage:
    python keygen_cli.py --count 10 --days 30 --format txt
    python keygen_cli.py --count 5 --days 0 --format json
"""
import argparse
from keygen import generate_bulk, generate_bulk_with_expiry, export_txt, export_json


def main():
    parser = argparse.ArgumentParser(description="KeyAuth License Key Generator")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of keys to generate")
    parser.add_argument("-d", "--days", type=int, default=30, help="Expiry in days (0 = no expiry)")
    parser.add_argument("-f", "--format", choices=["txt", "json", "print"], default="print", help="Output format")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output filename")
    args = parser.parse_args()

    if args.days > 0:
        keys = generate_bulk_with_expiry(args.count, args.days)
    else:
        keys = generate_bulk(args.count)

    if args.format == "print":
        for k in keys:
            if isinstance(k, dict):
                print(f"{k['license_key']}  (expires: {k['expires']})")
            else:
                print(k)

    elif args.format == "txt":
        key_list = [k["license_key"] if isinstance(k, dict) else k for k in keys]
        filename = args.output or "keys.txt"
        export_txt(key_list, filename)

    elif args.format == "json":
        key_list = keys if isinstance(keys[0], dict) else [{"license_key": k} for k in keys]
        filename = args.output or "keys.json"
        export_json(key_list, filename)


if __name__ == "__main__":
    main()
