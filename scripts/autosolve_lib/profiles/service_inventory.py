"""Rootless inventory of only caller-assigned TCP endpoints."""

import ipaddress
import re
import socket
import time

from .service_transport import _Stop, _connect


MAX_PORTS = 16
MAX_PROBE = 256
MAX_RESPONSE = 1024
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_HEX = frozenset("0123456789abcdefABCDEF")


def _validate(scope, timeout):
    if (not isinstance(scope, dict) or set(scope) != {"host", "ports"} or
            not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
            not 0 < timeout <= 10):
        raise ValueError("inventory requires host, ports and a timeout of at most 10 seconds")
    host = scope["host"]
    if not isinstance(host, str) or not 0 < len(host) <= 253:
        raise ValueError("host must be one assigned address or hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not all(_HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise ValueError("host must be one assigned address or hostname") from None
    entries = scope["ports"]
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_PORTS:
        raise ValueError(f"ports must be a list of 1 to {MAX_PORTS} explicit TCP ports")
    normalized = []
    seen = set()
    for entry in entries:
        if isinstance(entry, dict):
            if not set(entry) <= {"port", "probe_hex"} or "port" not in entry:
                raise ValueError("port entry needs only port and optional probe_hex")
            port = entry["port"]
            hex_data = entry.get("probe_hex", "")
            if (not isinstance(hex_data, str) or len(hex_data) > MAX_PROBE * 2 or
                    len(hex_data) % 2 or any(char not in _HEX for char in hex_data)):
                raise ValueError("probe_hex must contain at most 256 declared bytes")
            probe = bytes.fromhex(hex_data)
        else:
            port, probe = entry, b""
        if type(port) is not int or not 0 < port <= 65535 or port in seen:
            raise ValueError("ports must be unique TCP numbers from 1 to 65535")
        seen.add(port)
        normalized.append((port, probe))
    return host, normalized


def _hypotheses(response):
    if not re.match(rb"HTTP/(?:1\.[01]|2|3) [1-5][0-9]{2}(?: [^\r\n]{0,64})?\r\n", response):
        return None, None
    service = {"name": "http", "basis": "response_status_line", "verified": False}
    version = None
    header, end, _ = response.partition(b"\r\n\r\n")
    if end:
        for line in header.split(b"\r\n")[1:]:
            if line.lower().startswith(b"server:"):
                value = line[7:].strip()[:128].decode("ascii", "replace")
                version = {"value": value, "basis": "untrusted_server_header", "verified": False}
                break
    return service, version


def run_inventory(scope, *, timeout=5):
    """Connect to finite assigned TCP ports; return JSON-safe observations and warnings.

    Only a caller-declared probe is sent. The raw hex response is authoritative;
    labels derived from protocol text remain unverified hypotheses.
    """
    host, entries = _validate(scope, timeout)
    deadline = time.monotonic() + timeout
    report = {"status": "complete", "host": host, "ports": []}
    warnings = []
    for index, (port, probe) in enumerate(entries):
        row = {"port": port, "protocol": "tcp", "state": "unknown", "peer": None,
               "probe_hex": probe.hex(), "request_hex": "", "response_hex": "",
               "response_status": None,
               "service_hypothesis": None, "version_hint": None}
        report["ports"].append(row)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            row["response_status"] = "budget_exhausted"
            warnings.append(f"port {port}: inventory time budget exhausted")
            continue
        port_deadline = time.monotonic() + remaining / (len(entries) - index)
        response = bytearray()
        try:
            with _connect(host, port, port_deadline) as conn:
                row["state"] = "open"
                row["peer"] = list(conn.getpeername()[:2])
                if probe:
                    sent = 0
                    while sent < len(probe):
                        remaining = port_deadline - time.monotonic()
                        if remaining <= 0:
                            raise socket.timeout()
                        conn.settimeout(remaining)
                        count = conn.send(probe[sent:])
                        if count == 0:
                            raise ConnectionResetError("socket closed during declared probe")
                        sent += count
                        row["request_hex"] = probe[:sent].hex()
                while len(response) < MAX_RESPONSE:
                    remaining = port_deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout()
                    conn.settimeout(remaining)
                    chunk = conn.recv(min(4096, MAX_RESPONSE - len(response)))
                    if not chunk:
                        row["response_status"] = "eof"
                        break
                    response.extend(chunk)
                else:
                    row["response_status"] = "limit"
                    warnings.append(f"port {port}: response reached {MAX_RESPONSE}-byte limit")
        except ConnectionRefusedError:
            if row["state"] == "unknown":
                row["state"] = "closed"
                row["response_status"] = "connection_refused"
            else:
                row["response_status"] = "connection_refused_after_open"
                warnings.append(f"port {port}: connection refused after TCP connect")
        except _Stop as exc:
            row["response_status"] = exc.code
            warnings.append(f"port {port}: {exc}")
        except socket.timeout:
            row["response_status"] = "timeout_after_data" if response else "timeout"
            warnings.append(f"port {port}: connection or response timed out")
        except OSError as exc:
            row["response_status"] = type(exc).__name__
            warnings.append(f"port {port}: {type(exc).__name__}")
        row["response_hex"] = response.hex()
        row["service_hypothesis"], row["version_hint"] = _hypotheses(response)
    if warnings:
        report["status"] = "partial"
    return report, warnings
