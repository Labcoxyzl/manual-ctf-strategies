"""Small WEB05 differential checks at one explicitly selected GET parameter."""

import base64
import hashlib
import http.client
import re
import secrets
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit

from .web_static import _origin, _scope


MAX_BODY = 64 * 1024
_PARAMETER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}\Z")


def _validate(scope, timeout, max_requests, rate):
    if not isinstance(scope, dict) or scope.get("kind") not in ("traversal", "template"):
        raise ValueError("WEB05 needs one selected traversal or template check")
    required = {"origin", "request", "parameter", "kind", "expected"}
    allowed = required | ({"probe_value"} if scope["kind"] == "traversal" else {"syntax"})
    if set(scope) - allowed or not required <= set(scope) or (scope["kind"] == "traversal" and
                                                            "probe_value" not in scope):
        raise ValueError("WEB05 needs an explicit input point and expected response")
    parsed_origin = _origin(scope["origin"])
    origin = urlsplit(scope["origin"])
    request = scope["request"]
    if not isinstance(request, dict) or set(request) - {"method", "path", "query", "headers"}:
        raise ValueError("request may contain only method, path, query and headers")
    path = request.get("path")
    if (request.get("method") != "GET" or not isinstance(path, str) or
            not path.startswith("/") or path.startswith("//") or len(path) > 2048 or
            any(ord(char) < 33 or ord(char) > 126 for char in path) or
            "?" in path or "#" in path):
        raise ValueError("WEB05 requires one bodyless same-origin GET path")
    query = request.get("query")
    parameter = scope["parameter"]
    if (not isinstance(query, dict) or not 0 < len(query) <= 16 or
            not isinstance(parameter, str) or not _PARAMETER.fullmatch(parameter) or
            parameter not in query or any(not isinstance(key, str) or
                not _PARAMETER.fullmatch(key) or not isinstance(value, str) or
                len(value) > 256 or any(ord(char) < 32 for char in value)
                for key, value in query.items())):
        raise ValueError("WEB05 requires one existing bounded query parameter")
    headers = request.get("headers", {})
    forbidden = {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}
    if (not isinstance(headers, dict) or len(headers) > 16 or
            any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", key)
                or key.lower() in forbidden or not isinstance(value, str) or
                len(value) > 2048 or any(ord(char) < 32 or ord(char) > 126 for char in value)
                for key, value in headers.items())):
        raise ValueError("WEB05 request headers must be bounded and cannot change framing")
    expected = scope["expected"]
    if (not isinstance(expected, str) or not 0 < len(expected) <= 128 or
            any(ord(char) < 32 for char in expected)):
        raise ValueError("WEB05 requires one bounded expected response marker")
    if scope["kind"] == "template":
        if expected != "323":
            raise ValueError("template expected marker must match the fixed arithmetic probe")
        if scope.get("syntax", "braces") not in ("braces", "dollar"):
            raise ValueError("template syntax must be braces or dollar")
    else:
        value = scope["probe_value"]
        if (not isinstance(value, str) or not 0 < len(value) <= 128 or
                value.startswith(("/", "//")) or "://" in value or
                any(ord(char) < 33 or ord(char) > 126 or char in "?&#\\" for char in value)
                or expected in value or expected in query[parameter]):
            raise ValueError("traversal probe must be one selected relative path with a separate marker")
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
            not 0 < timeout <= 30 or type(max_requests) is not int or
            not 1 <= max_requests <= 4 or not isinstance(rate, (int, float)) or
            isinstance(rate, bool) or not 0 < rate <= 20):
        raise ValueError("WEB05 requires at most four requests, 30 seconds and 20 requests/second")
    return parsed_origin, origin, path, query, headers


def _probe(origin, parsed_origin, path, query, headers, parameter, value, deadline):
    target = path + "?" + urlencode({**query, parameter: value})
    request_headers = {**headers, "Host": origin.netloc, "Connection": "close",
                       "Accept-Encoding": "identity"}
    row = {"value": value, "request": {"method": "GET", "target": target,
                                        "headers": request_headers},
           "response": {"status": None, "reason": None, "headers": [],
                        "body_base64": None, "body_text": None, "body_sha256": None,
                        "bytes_read": 0, "truncated": False},
           "redirect_scope": None, "error": None}
    connection = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        cls = http.client.HTTPSConnection if parsed_origin[0] == "https" else http.client.HTTPConnection
        connection = cls(origin.hostname, parsed_origin[2], timeout=remaining)
        connection.request("GET", target, headers=request_headers)
        response = connection.getresponse()
        row["response"].update(status=response.status, reason=response.reason,
                               headers=response.getheaders())
        body = bytearray()
        try:
            while len(body) <= MAX_BODY:
                if time.monotonic() >= deadline:
                    raise TimeoutError
                chunk = response.read1(min(4096, MAX_BODY + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
        finally:
            row["response"].update(body_base64=base64.b64encode(body).decode("ascii"),
                                   body_text=body.decode("utf-8", "replace"),
                                   body_sha256=hashlib.sha256(body).hexdigest(),
                                   bytes_read=len(body), truncated=len(body) > MAX_BODY)
        location = response.getheader("Location")
        if response.status in (301, 302, 303, 307, 308) and location:
            row["redirect_scope"] = _scope(location, parsed_origin)
    except (TimeoutError, socket.timeout, OSError, http.client.HTTPException, ssl.SSLError) as exc:
        row["error"] = type(exc).__name__
    finally:
        if connection:
            connection.close()
    return row


def probe_web_leads(scope, *, timeout=10, max_requests=4, rate=5):
    """Return candidate leads only; never follow redirects or fetch another origin."""
    parsed_origin, origin, path, query, headers = _validate(scope, timeout, max_requests, rate)
    parameter = scope["parameter"]
    control = "autosolve-" + secrets.token_hex(8)
    if scope["kind"] == "traversal":
        values = [query[parameter], control, "autosolve-" + secrets.token_hex(12),
                  scope["probe_value"]]
    else:
        opener, closer = ("{{", "}}") if scope.get("syntax", "braces") == "braces" else ("${", "}")
        values = [query[parameter], control, f"{opener}17*20{closer}",
                  f"{opener}17*19{closer}"]
    report = {"status": "partial", "kind": scope["kind"], "origin": scope["origin"],
              "parameter": parameter, "expected": scope["expected"],
              "classification": "ambiguous", "calibration": "incomplete",
              "requests": [], "requests_used": 0,
              "budget": {"timeout": timeout, "max_requests": max_requests, "rate": rate}}
    warnings = []
    deadline = time.monotonic() + timeout
    next_request = time.monotonic()
    for value in values:
        if report["requests_used"] >= max_requests or time.monotonic() >= deadline:
            warnings.append("WEB05 request or time budget exhausted")
            break
        if next_request > time.monotonic():
            time.sleep(min(next_request - time.monotonic(), max(0, deadline - time.monotonic())))
        if time.monotonic() >= deadline:
            warnings.append("WEB05 time budget exhausted")
            break
        report["requests"].append(_probe(origin, parsed_origin, path, query, headers,
                                         parameter, value, deadline))
        report["requests_used"] += 1
        next_request = time.monotonic() + 1 / rate
    if len(report["requests"]) != 4:
        return report, warnings
    responses = [row["response"] for row in report["requests"]]
    if any(row["error"] or response["truncated"] or
           response["status"] in (None, 429, 503) or
           row["redirect_scope"] is not None
           for row, response in zip(report["requests"], responses)):
        warnings.append("WEB05 response incomplete, throttled or redirected")
        return report, warnings
    bodies = [response["body_text"] for response in responses]
    expected = scope["expected"]
    if scope["kind"] == "traversal":
        signatures = [(response["status"], response["body_sha256"])
                      for response in responses[1:3]]
        report["calibration"] = "stable" if signatures[0] == signatures[1] else "unstable"
        if report["calibration"] != "stable":
            warnings.append("WEB05 soft-404 controls differ")
            return report, warnings
        lead = (200 <= responses[3]["status"] < 300 and expected in bodies[3] and
                all(expected not in body for body in bodies[:3]))
    else:
        report["calibration"] = "paired_arithmetic"
        lead = (all(200 <= response["status"] < 300 for response in responses[2:]) and
                "340" in bodies[2] and "323" not in bodies[2] and
                "323" in bodies[3] and "340" not in bodies[3] and
                all("323" not in body and "340" not in body for body in bodies[:2]))
    report["classification"] = "candidate" if lead else "negative"
    report["status"] = "complete"
    return report, warnings
