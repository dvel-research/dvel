#!/usr/bin/env python3
import base64
import binascii
import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: cert_hex.py <cert.pem>", file=sys.stderr)
        return 2
    path = sys.argv[1]
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    matches = re.findall(
        b"-----BEGIN CERTIFICATE-----\\s*(.*?)\\s*-----END CERTIFICATE-----",
        data,
        re.S,
    )
    if not matches:
        print("error: no PEM certificate found", file=sys.stderr)
        return 1

    try:
        der = base64.b64decode(matches[0])
    except (binascii.Error, ValueError) as exc:
        print(f"error: invalid PEM data ({exc})", file=sys.stderr)
        return 1

    print(binascii.hexlify(der).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
