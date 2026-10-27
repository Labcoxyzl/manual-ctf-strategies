"""Bounded WEB02 discovery against one explicitly supplied HTTP origin."""

import hashlib
import http.client
import re
import secrets
import socket
import ssl
import time
from urllib.parse import quote, urlencode, urlsplit

from .web_static import _origin, _scope


MAX_BODY = 64 * 1024
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_PATH_WORD = re.compile(r"[A-Za-z0-9._~/-]{1,128}\Z")
_PARAMETER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")


def _validate(scope, timeout, max_requests, rate):
    if (not isinstance(scope, dict) or set(scope) != {"origin", "request", "dictionary", "kind"}
            or scope["kind"] not in ("path", "parameter", "vhost")):
        raise ValueError("web discovery requires kind, origin, request and dictionary")
    origin = scope["origin"]
    parsed_origin = _origin(origin)
    parts = urlsplit(origin)
    request = scope["request"]
    if not isinstance(request, dict) or set(request) - {"method", "path", "query", "headers"}:
        raise ValueError("request may contain only method, path, query and headers")
    if request.get("method") != "GET":
        raise ValueError("bounded discovery currently requires an explicit GET request")
    path = request.get("path")
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or len(path) > 2048 or any(ord(char) < 33 or ord(char) > 126 for char in path)
            or "?" in path or "#" in path):
        raise ValueError("request path must be one bounded absolute URL path")
    query = request.get("query", {})
    headers = request.get("headers", {})
    if (not isinstance(query, dict) or len(query) > 16 or
            any(not isinstance(key, str) or not _PARAMETER.fullmatch(key) or
                not isinstance(value, str) or len(value) > 256 for key, value in query.items())):
        raise ValueError("query must contain at most 16 bounded string parameters")
    if (not isinstance(headers, dict) or len(headers) > 16 or
            any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key) or
                key.lower() in ("host", "content-length", "transfer-encoding", "connection") or
                not isinstance(value, str) or len(value) > 2048 or
                any(ord(char) < 32 or ord(char) > 126 for char in value)
                for key, value in headers.items())):
        raise ValueError("request headers must be bounded and cannot override connection framing")
    words = scope["dictionary"]
    if (not isinstance(words, list) or not 0 < len(words) <= 32 or
            any(not isinstance(word, str) or not word for word in words) or
            len(set(words)) != len(words)):
        raise ValueError("dictionary must contain 1 to 32 unique words")
    for word in words:
        if scope["kind"] == "path":
            valid = (_PATH_WORD.fullmatch(word) and not word.startswith("/") and
                     all(part not in ("", ".", "..") for part in word.split("/")))
        elif scope["kind"] == "parameter":
            valid = _PARAMETER.fullmatch(word) and word not in query
        else:
            valid = (len(word) <= 253 and all(_HOST_LABEL.fullmatch(label)
                                              for label in word.split(".")))
        if not valid:
            raise ValueError(f"invalid {scope['kind']} dictionary word")
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
            not 0 < timeout <= 30 or type(max_requests) is not int or
            not 3 <= max_requests <= 64 or not isinstance(rate, (int, float)) or
            isinstance(rate, bool) or not 0 < rate <= 20):
        raise ValueError("web discovery requires bounded time, request and rate budgets")
    return parsed_origin, parts, path, query, headers, words


def _target(kind, path, query, word):
    if kind == "path":
        path = path.rstrip("/") + "/" + quote(word, safe="/._~-")
    elif kind == "parameter":
        query = {**query, word: "1"}
    return path + ("?" + urlencode(query) if query else "")


def _probe(origin, parsed_origin, kind, path, query, headers, word, deadline):
    target = _target(kind, path, query, word)
    host = word if kind == "vhost" else origin.netloc
    request_headers = {**headers, "Host": host, "Connection": "close"}
    if not any(key.lower() == "accept-encoding" for key in headers):
        request_headers["Accept-Encoding"] = "identity"
    row = {"candidate": word, "request": {"method": "GET", "target": target,
                                            "host": host, "headers": request_headers},
           "response": {"status": None, "reason": None, "headers": {}, "bytes_read": 0,
                        "body_sha256": None, "truncated": False},
           "redirect_scope": None, "classification": "ambiguous", "error": None}
    connection = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        port = parsed_origin[2]
        connection = (http.client.HTTPSConnection(origin.hostname, port, timeout=remaining)
                      if parsed_origin[0] == "https" else
                      http.client.HTTPConnection(origin.hostname, port, timeout=remaining))
        connection.request("GET", target, headers=request_headers)
        response = connection.getresponse()
        row["response"].update(status=response.status, reason=response.reason,
                               headers={key.lower(): value for key, value in response.getheaders()
                                        if key.lower() in ("content-length", "location")})
        body = bytearray()
        try:
            while len(body) <= MAX_BODY:
                if time.monotonic() >= deadline:
                    raise TimeoutError
                chunk = response.read1(min(4096, MAX_BODY + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
        except (TimeoutError, socket.timeout, OSError, http.client.HTTPException) as exc:
            row["error"] = type(exc).__name__
            row["classification"] = "error"
        row["response"].update(bytes_read=len(body),
                               body_sha256=hashlib.sha256(body).hexdigest(),
                               truncated=len(body) > MAX_BODY)
        location = row["response"]["headers"].get("location")
        if response.status in (301, 302, 303, 307, 308) and location:
            row["redirect_scope"] = _scope(location, parsed_origin)
    except (TimeoutError, socket.timeout, OSError, http.client.HTTPException, ssl.SSLError) as exc:
        row["error"] = type(exc).__name__
        row["classification"] = "error"
    finally:
        if connection:
            connection.close()
    return row


def discover_web(scope, *, timeout=10, max_requests=32, rate=5):
    """Probe only a declared origin; redirects and discovered URLs are never fetched."""
    parsed_origin, origin, path, query, headers, words = _validate(
        scope, timeout, max_requests, rate)
    deadline = time.monotonic() + timeout
    kind = scope["kind"]
    controls = (["autosolve-" + secrets.token_hex(6), "autosolve-" + secrets.token_hex(11)]
                if kind != "vhost" else
                ["autosolve-" + secrets.token_hex(6) + ".invalid",
                 "autosolve-" + secrets.token_hex(11) + ".invalid"])
    report = {"status": "complete", "kind": kind, "origin": scope["origin"],
              "calibration": "incomplete", "controls": [], "results": [],
              "requests_used": 0, "budget": {"timeout": timeout,
                                             "max_requests": max_requests, "rate": rate}}
    warnings = []
    next_request = time.monotonic()
    for index, word in enumerate(controls + words):
        if report["requests_used"] >= max_requests:
            warnings.append("web request budget exhausted")
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0 or next_request >= deadline:
            warnings.append("web time budget exhausted")
            break
        time.sleep(min(max(0, next_request - time.monotonic()), remaining))
        if time.monotonic() >= deadline:
            warnings.append("web time budget exhausted")
            break
        started = time.monotonic()
        row = _probe(origin, parsed_origin, kind, path, query, headers, word, deadline)
        report["requests_used"] += 1
        (report["controls"] if index < 2 else report["results"]).append(row)
        next_request = started + 1 / rate
        if row["error"]:
            warnings.append(f"web request {index + 1}: {row['error']}")
    controls_seen = report["controls"]
    if len(controls_seen) == 2 and all(not row["error"] and
                                       not row["response"]["truncated"] and
                                       row["response"]["status"] not in (429, 503)
                                       for row in controls_seen):
        signatures = [(row["response"]["status"], row["response"]["bytes_read"],
                       row["response"]["body_sha256"]) for row in controls_seen]
        report["calibration"] = "stable" if signatures[0] == signatures[1] else "unstable"
    if report["calibration"] != "stable":
        warnings.append("web soft-404 calibration incomplete or unstable")
    else:
        baseline = controls_seen[0]["response"]
        for row in report["results"]:
            response = row["response"]
            if row["error"]:
                continue
            if (response["truncated"] or response["status"] in (429, 503) or
                    row["redirect_scope"] in ("cross_origin", "invalid", "non_http")):
                row["classification"] = "ambiguous"
            elif (response["status"] == baseline["status"] and
                  response["bytes_read"] == baseline["bytes_read"] and
                  response["body_sha256"] == baseline["body_sha256"]):
                row["classification"] = "soft_404"
            elif (response["status"] != baseline["status"] or
                  response["bytes_read"] != baseline["bytes_read"]):
                row["classification"] = "candidate"
    if (len(report["results"]) < len(words) or warnings or
            any(row["classification"] in ("ambiguous", "error") for row in report["results"])):
        report["status"] = "partial"
    return report, warnings
