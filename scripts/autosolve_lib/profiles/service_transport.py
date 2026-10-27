"""Bounded, explicit service reads and writes with exact byte transcripts."""

import os
import select
import signal
import socket
import ssl
import stat
import subprocess
import threading
import time


MAX_BYTES = 8 * 1024 * 1024
MAX_CA_BYTES = 1024 * 1024


class _Stop(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _positive_int(value, name, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError(f"{name} must be an integer from 1 to {maximum}")
    return value


def _hex(value, name, *, allow_empty=False):
    if (not isinstance(value, str) or len(value) % 2 or len(value) > MAX_BYTES * 2 or
            any(char not in "0123456789abcdefABCDEF" for char in value)):
        raise ValueError(f"{name} must be bounded hexadecimal bytes")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be hexadecimal bytes") from exc
    if not allow_empty and not data:
        raise ValueError(f"{name} must not be empty")
    return data


def _read_ca(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as exc:
        raise ValueError("CA file must be a regular certificate file") from exc
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError("CA file must be a regular certificate file")
        data = source.read(MAX_CA_BYTES + 1)
    if not data or len(data) > MAX_CA_BYTES:
        raise ValueError("CA file must contain at most 1 MiB of certificates")
    try:
        return data.decode("ascii") if b"-----BEGIN CERTIFICATE-----" in data else data
    except UnicodeDecodeError as exc:
        raise ValueError("CA file contains invalid PEM text") from exc


def _validate(protocol, *, timeout, max_bytes, max_steps, allow_local):
    if not isinstance(protocol, dict) or set(protocol) != {"transport", "steps"}:
        raise ValueError("protocol needs only transport and steps")
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 120:
        raise ValueError("timeout must be positive and at most 120 seconds")
    _positive_int(max_bytes, "max_bytes", MAX_BYTES)
    _positive_int(max_steps, "max_steps", 128)
    transport = protocol["transport"]
    if not isinstance(transport, dict):
        raise ValueError("transport must be an object")
    if "argv" in transport:
        if set(transport) - {"argv", "cwd"} or not allow_local:
            raise ValueError("local execution requires explicit permission")
        argv = transport["argv"]
        if (not isinstance(argv, list) or not 0 < len(argv) <= 16 or
                any(not isinstance(arg, str) or not 0 < len(arg) <= 4096 for arg in argv)):
            raise ValueError("argv must contain 1 to 16 bounded strings")
        if "cwd" in transport and (not isinstance(transport["cwd"], str) or
                                   not transport["cwd"]):
            raise ValueError("cwd must be a nonempty path")
    else:
        if set(transport) - {"host", "port", "tls", "ca_file", "server_hostname"}:
            raise ValueError("unsupported TCP transport field")
        host = transport.get("host")
        if not isinstance(host, str) or not 0 < len(host) <= 253:
            raise ValueError("host must be a bounded hostname or address")
        _positive_int(transport.get("port"), "port", 65535)
        if type(transport.get("tls", False)) is not bool:
            raise ValueError("tls must be a boolean")
        if not transport.get("tls") and ({"ca_file", "server_hostname"} & set(transport)):
            raise ValueError("TLS options require tls=true")
        for name in ("ca_file", "server_hostname"):
            if name in transport and (not isinstance(transport[name], str) or
                                      not 0 < len(transport[name]) <= 4096):
                raise ValueError(f"{name} must be a bounded string")

    ca_data = _read_ca(transport["ca_file"]) if "ca_file" in transport else None
    steps = protocol["steps"]
    if not isinstance(steps, list) or not 0 < len(steps) <= max_steps:
        raise ValueError("steps must be a nonempty bounded list")
    normalized = []
    write_total = 0
    for index, step in enumerate(steps):
        if not isinstance(step, dict) or len(step) != 1:
            raise ValueError(f"step {index} must contain one explicit action")
        if "write_hex" in step:
            data = _hex(step["write_hex"], f"step {index} write_hex", allow_empty=True)
            write_total += len(data)
            if write_total > max_bytes:
                raise ValueError("declared writes exceed byte limit")
            normalized.append(("write", data))
            continue
        if "read" not in step or not isinstance(step["read"], dict):
            raise ValueError(f"step {index} has no supported read or write")
        framing = step["read"]
        keys = set(framing)
        if "delimiter_hex" in framing and keys == {"delimiter_hex"}:
            delimiter = _hex(framing["delimiter_hex"], "delimiter_hex")
            if len(delimiter) > 32:
                raise ValueError("delimiter exceeds 32 bytes")
            normalized.append(("delimiter", delimiter))
        elif "length_bytes" in framing and keys <= {"length_bytes", "byteorder"}:
            width = framing["length_bytes"]
            if type(width) is not int or width not in (1, 2, 4):
                raise ValueError("length_bytes must be 1, 2 or 4")
            byteorder = framing.get("byteorder", "big")
            if byteorder not in ("big", "little"):
                raise ValueError("byteorder must be big or little")
            normalized.append(("length", (width, byteorder)))
        elif "exact_bytes" in framing and keys == {"exact_bytes"}:
            normalized.append(("exact", _positive_int(framing["exact_bytes"],
                                                        "exact_bytes", max_bytes)))
        else:
            raise ValueError(f"step {index} has ambiguous or unsupported framing")
    return transport, normalized, ca_data


def _close_process(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=.2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=.2)
    except subprocess.TimeoutExpired:
        pass
    process.stdin.close()
    process.stdout.close()


def _connect(host, port, deadline):
    resolved = {}
    done = threading.Event()

    def resolve():
        try:
            resolved["addresses"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            resolved["error"] = exc
        finally:
            done.set()

    # shortcut: a timed-out DNS thread may finish later; CLI exits after this bounded run.
    threading.Thread(target=resolve, daemon=True).start()
    if not done.wait(max(0, deadline - time.monotonic())):
        raise _Stop("timeout", "service DNS time limit reached")
    if "error" in resolved:
        raise resolved["error"]
    last_error = OSError("service address resolution returned no endpoints")
    for family, socktype, proto, _, address in resolved["addresses"]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Stop("timeout", "service connection time limit reached")
        attempt = socket.socket(family, socktype, proto)
        attempt.settimeout(remaining)
        try:
            attempt.connect(address)
            return attempt
        except OSError as exc:
            last_error = exc
            attempt.close()
    raise last_error


def run_service(protocol, *, timeout=10, max_bytes=1024 * 1024,
                max_steps=32, max_frame_bytes=None, allow_local=False):
    """Run only declared steps. Return a JSON-safe report and warning list.

    A local argv requires the caller's explicit allow_local authorization; a
    protocol file alone must never enable process execution.
    """
    transport, steps, ca_data = _validate(protocol, timeout=timeout, max_bytes=max_bytes,
                                          max_steps=max_steps, allow_local=allow_local)
    max_frame_bytes = min(65536, max_bytes) if max_frame_bytes is None else max_frame_bytes
    _positive_int(max_frame_bytes, "max_frame_bytes", max_bytes)
    start = time.monotonic()
    deadline = start + timeout
    report = {"status": "partial", "error": None, "transport": {"kind": "process" if
              "argv" in transport else "tcp", "tls": bool(transport.get("tls", False))},
              "transcript": [], "frames": [], "pending_hex": "", "bytes_received": 0,
              "bytes_sent": 0}
    warnings = []
    process = None
    sock = None
    pending = bytearray()
    consumed = 0

    def wait(fd, reading):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _Stop("timeout", "service time limit reached")
        ready = select.select([fd] if reading else [], [] if reading else [fd], [], remaining)
        if not (ready[0] if reading else ready[1]):
            raise _Stop("timeout", "service time limit reached")

    def receive():
        if time.monotonic() >= deadline:
            raise _Stop("timeout", "service time limit reached")
        available = max_bytes - report["bytes_received"] - report["bytes_sent"]
        if available <= 0:
            raise _Stop("byte_limit", "service byte limit reached")
        while True:
            try:
                data = os.read(process.stdout.fileno(), min(4096, available)) if process else (
                    sock.recv(min(4096, available)))
                break
            except ssl.SSLWantWriteError:
                wait(sock, False)
            except (BlockingIOError, ssl.SSLWantReadError):
                wait(process.stdout.fileno() if process else sock, True)
        if not data:
            raise _Stop("early_eof", "service closed before declared frame completed")
        report["transcript"].append({"direction": "recv", "offset": report["bytes_received"],
                                     "elapsed_ms": round((time.monotonic() - start) * 1000, 3),
                                     "hex": data.hex()})
        report["bytes_received"] += len(data)
        pending.extend(data)

    def send(data):
        offset = 0
        while offset < len(data):
            if time.monotonic() >= deadline:
                raise _Stop("timeout", "service time limit reached")
            try:
                sent = os.write(process.stdin.fileno(), data[offset:]) if process else sock.send(
                    data[offset:])
            except ssl.SSLWantReadError:
                wait(sock, True)
                continue
            except (BlockingIOError, ssl.SSLWantWriteError):
                wait(process.stdin.fileno() if process else sock, False)
                continue
            if not sent:
                raise _Stop("early_eof", "service closed during declared write")
            chunk = data[offset:offset + sent]
            report["transcript"].append({"direction": "send", "offset": report["bytes_sent"],
                                         "elapsed_ms": round((time.monotonic() - start) * 1000, 3),
                                         "hex": chunk.hex()})
            report["bytes_sent"] += sent
            offset += sent

    def need(size):
        while len(pending) < size:
            if size > max_frame_bytes:
                raise _Stop("frame_limit", "declared frame exceeds frame byte limit")
            receive()

    try:
        if "argv" in transport:
            process = subprocess.Popen(transport["argv"], cwd=transport.get("cwd"),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stdin.fileno(), False)
        else:
            sock = _connect(transport["host"], transport["port"], deadline)
            if transport.get("tls"):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _Stop("timeout", "service time limit reached")
                sock.settimeout(remaining)
                context = ssl.create_default_context(cadata=ca_data)
                sock = context.wrap_socket(sock, server_hostname=transport.get(
                    "server_hostname", transport["host"]))
            sock.setblocking(False)
        for kind, argument in steps:
            if kind == "write":
                if len(argument) + report["bytes_received"] + report["bytes_sent"] > max_bytes:
                    raise _Stop("byte_limit", "service byte limit reached")
                send(argument)
                continue
            frame_start = consumed
            if kind == "exact":
                need(argument)
                size = argument
                payload_start = 0
            elif kind == "length":
                width, byteorder = argument
                need(width)
                declared = int.from_bytes(pending[:width], byteorder)
                size = width + declared
                need(size)
                payload_start = width
            else:
                delimiter = argument
                while True:
                    end = pending.find(delimiter)
                    if end >= 0:
                        size = end + len(delimiter)
                        payload_start = 0
                        break
                    if len(pending) >= max_frame_bytes:
                        raise _Stop("frame_limit", "delimiter frame exceeds frame byte limit")
                    receive()
                if size > max_frame_bytes:
                    raise _Stop("frame_limit", "delimiter frame exceeds frame byte limit")
            wire = bytes(pending[:size])
            del pending[:size]
            consumed += size
            report["frames"].append({"framing": kind, "start_offset": frame_start,
                                     "end_offset": consumed, "elapsed_ms": round(
                                         (time.monotonic() - start) * 1000, 3),
                                     "wire_hex": wire.hex(),
                                     "payload_hex": wire[payload_start:].hex()})
        report["status"] = "complete"
    except _Stop as exc:
        report["error"] = exc.code
        warnings.append(str(exc))
    except KeyboardInterrupt:
        report["error"] = "interrupted"
        warnings.append("service interrupted; recorded transcript is incomplete")
    except TimeoutError:
        report["error"] = "timeout"
        warnings.append("service time limit reached")
    except (OSError, ssl.SSLError) as exc:
        report["error"] = "transport_error"
        warnings.append(f"service transport error: {type(exc).__name__}")
    finally:
        report["pending_hex"] = pending.hex()
        if sock is not None:
            sock.close()
        if process is not None:
            _close_process(process)
    return report, warnings
