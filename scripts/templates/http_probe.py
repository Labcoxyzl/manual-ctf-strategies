#!/usr/bin/env python3
"""Editable single-request HTTP experiment; no redirects or retries."""
import argparse
import math
import sys
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_BODY = 65536
MAX_HEADERS = 40
MAX_HEADER_VALUE = 512
HEADERS = {"User-Agent": "ctf-template/1.0"}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="explicit http:// or https:// challenge URL")
    parser.add_argument("--data", help="send this UTF-8 text as a POST body; default is GET")
    parser.add_argument("--timeout", type=float, default=5.0, help="socket timeout in seconds")
    args = parser.parse_args()
    try:
        parsed = urlsplit(args.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None:
            raise ValueError("URL must use http(s), include a host, and omit embedded credentials")
        parsed.port
    except ValueError as error:
        parser.error(str(error))
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and positive")
    body = args.data.encode("utf-8") if args.data is not None else None
    headers = dict(HEADERS)
    if body is not None:
        headers["Content-Type"] = "text/plain; charset=utf-8"
    try:
        request = Request(args.url, data=body, headers=headers)
        try:
            response = build_opener(NoRedirect()).open(request, timeout=args.timeout)
        except HTTPError as error:
            response = error
        with response:
            print(f"HTTP {response.status} {response.reason!r}", flush=True)
            for index, (name, value) in enumerate(response.headers.items()):
                if index == MAX_HEADERS:
                    print(f"Headers: additional fields omitted after {MAX_HEADERS}")
                    break
                suffix = " [value truncated]" if len(value) > MAX_HEADER_VALUE else ""
                if name.lower() == "location":
                    suffix += " (not followed)"
                print(f"Header {name!r}: {value[:MAX_HEADER_VALUE]!r}{suffix}")
            transfer = response.headers.get("Transfer-Encoding", "").strip().lower()
            if transfer not in ("", "chunked"):
                raise ValueError(f"unsupported Transfer-Encoding: {transfer!r}")
            expected_length = None
            if response.status not in (204, 304) and transfer != "chunked":
                lengths = response.headers.get_all("Content-Length", [])
                if lengths:
                    if any(not value.strip().isascii() or not value.strip().isdecimal() for value in lengths):
                        raise ValueError("invalid Content-Length")
                    sizes = {int(value.strip()) for value in lengths}
                    if len(sizes) != 1:
                        raise ValueError("conflicting Content-Length headers")
                    expected_length = sizes.pop()
            data = response.read(MAX_BODY + 1)
            print(f"Body: {data[:MAX_BODY]!r}")
            if len(data) > MAX_BODY:
                print(f"Failed: response exceeds {MAX_BODY} bytes; preview truncated", file=sys.stderr)
                return 1
            if expected_length is not None and len(data) != expected_length:
                print(f"Failed: incomplete body; expected {expected_length} bytes, received {len(data)}", file=sys.stderr)
                return 1
            return 0 if 200 <= response.status < 300 else 1
    except (OSError, URLError, ValueError, HTTPException) as error:
        print(f"Failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
