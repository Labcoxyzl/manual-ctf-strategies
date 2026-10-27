"""Solve only a caller-declared, bounded integer arithmetic wire protocol."""

import socket
import time

from .service_transport import _connect, _Stop
try:
    from scripts.templates.math_client import solve
except ModuleNotFoundError:
    from templates.math_client import solve


def _hex(value, name, *, empty=False):
    if (not isinstance(value, str) or len(value) > 64 or len(value) % 2 or
            any(char not in "0123456789abcdefABCDEF" for char in value) or
            (not empty and not value)):
        raise ValueError(f"{name} must be bounded hexadecimal bytes")
    return bytes.fromhex(value)


def _ascii(value, name, *, empty=False):
    if not isinstance(value, str) or len(value) > 64 or (not empty and not value):
        raise ValueError(f"{name} must be bounded ASCII text")
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must be ASCII text") from exc


def _integer(value, name, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer from {low} to {high}")
    return value


def _validate(protocol, timeout, max_rounds, max_bytes, max_frame_bytes, max_integer):
    if not isinstance(protocol, dict) or set(protocol) != {
            "transport", "framing", "question", "completion", "response"}:
        raise ValueError("protocol requires transport, framing, question, completion and response")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or
            not 0 < timeout <= 120):
        raise ValueError("timeout must be positive and at most 120 seconds")
    _integer(max_rounds, "max_rounds", 1, 10000)
    _integer(max_bytes, "max_bytes", 1, 8 * 1024 * 1024)
    _integer(max_frame_bytes, "max_frame_bytes", 1, min(65536, max_bytes))
    _integer(max_integer, "max_integer", 1, 10 ** 30)

    transport = protocol["transport"]
    if (not isinstance(transport, dict) or set(transport) != {"host", "port"} or
            not isinstance(transport["host"], str) or
            not 0 < len(transport["host"]) <= 253):
        raise ValueError("transport needs a bounded host and port")
    _integer(transport["port"], "port", 1, 65535)

    framing = protocol["framing"]
    if not isinstance(framing, dict) or set(framing) != {"delimiter_hex"}:
        raise ValueError("framing needs delimiter_hex")
    delimiter = _hex(framing["delimiter_hex"], "delimiter_hex")
    if len(delimiter) > 32:
        raise ValueError("delimiter exceeds 32 bytes")

    question = protocol["question"]
    if not isinstance(question, dict) or set(question) != {
            "prefix_ascii", "separator_ascii", "suffix_ascii", "first_id", "id_step"}:
        raise ValueError("question needs prefix, separator, suffix and round IDs")
    prefix = _ascii(question["prefix_ascii"], "question prefix_ascii")
    separator = _ascii(question["separator_ascii"], "question separator_ascii")
    suffix = _ascii(question["suffix_ascii"], "question suffix_ascii", empty=True)
    first = _integer(question["first_id"], "first_id", 0, 10 ** 9)
    step = _integer(question["id_step"], "id_step", 1, 10 ** 9)

    completion = protocol["completion"]
    if (not isinstance(completion, dict) or set(completion) - {
            "prefix_ascii", "min_suffix_bytes", "max_suffix_bytes", "min_rounds"} or
            not {"prefix_ascii", "min_suffix_bytes"} <= set(completion)):
        raise ValueError("completion needs a prefix and minimum suffix length")
    done_prefix = _ascii(completion["prefix_ascii"], "completion prefix_ascii")
    done_min = _integer(completion["min_suffix_bytes"], "min_suffix_bytes", 0,
                        max_frame_bytes)
    done_max = _integer(completion.get("max_suffix_bytes", max_frame_bytes),
                        "max_suffix_bytes", done_min, max_frame_bytes)
    done_rounds = _integer(completion.get("min_rounds", 1), "min_rounds", 1, max_rounds)
    if done_prefix.startswith(prefix) or prefix.startswith(done_prefix):
        raise ValueError("question and completion prefixes must be distinct")

    response = protocol["response"]
    if (not isinstance(response, dict) or set(response) != {
            "encoding", "prefix_hex", "suffix_hex"} or
            response["encoding"] != "ascii_decimal"):
        raise ValueError("response encoding must be declared as ascii_decimal")
    response_prefix = _hex(response["prefix_hex"], "response prefix_hex", empty=True)
    response_suffix = _hex(response["suffix_hex"], "response suffix_hex", empty=True)
    if not response_prefix and not response_suffix:
        raise ValueError("response needs a declared byte boundary")
    return (transport, delimiter, prefix, separator, suffix, first, step,
            done_prefix, done_min, done_max, done_rounds,
            response_prefix, response_suffix)


def run_arithmetic(protocol, *, timeout=10, max_rounds=100, max_bytes=65536,
                   max_frame_bytes=1024, max_integer=10 ** 30):
    """Exchange finite integer questions; return a JSON-safe report and warnings."""
    (transport, delimiter, prefix, separator, suffix, first, step, done_prefix,
     done_min, done_max, done_rounds, response_prefix, response_suffix) = _validate(
         protocol, timeout, max_rounds, max_bytes, max_frame_bytes, max_integer)
    started = time.monotonic()
    deadline = started + timeout
    report = {"status": "partial", "error": None, "transport": {"kind": "tcp",
              "host": transport["host"], "port": transport["port"]},
              "transcript": [], "frames": [], "rounds": [], "completion_hex": None,
              "pending_hex": "", "bytes_received": 0, "bytes_sent": 0}
    warnings = []
    pending = bytearray()
    consumed = 0
    sock = None

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise _Stop("timeout", "arithmetic service time limit reached")
        return left

    def receive():
        available = max_bytes - report["bytes_received"] - report["bytes_sent"]
        if available <= 0:
            raise _Stop("byte_limit", "arithmetic service byte limit reached")
        sock.settimeout(remaining())
        data = sock.recv(min(4096, available))
        if not data:
            raise _Stop("early_eof", "service closed before the terminal condition")
        report["transcript"].append({"direction": "recv", "offset": report["bytes_received"],
                                     "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                                     "hex": data.hex()})
        report["bytes_received"] += len(data)
        pending.extend(data)

    def send(data):
        if len(data) + report["bytes_received"] + report["bytes_sent"] > max_bytes:
            raise _Stop("byte_limit", "arithmetic service byte limit reached")
        offset = 0
        while offset < len(data):
            sock.settimeout(remaining())
            sent = sock.send(data[offset:])
            if not sent:
                raise _Stop("early_eof", "service closed during answer")
            chunk = data[offset:offset + sent]
            report["transcript"].append({"direction": "send", "offset": report["bytes_sent"],
                                         "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                                         "hex": chunk.hex()})
            report["bytes_sent"] += sent
            offset += sent

    try:
        sock = _connect(transport["host"], transport["port"], deadline)
        while True:
            while True:
                end = pending.find(delimiter)
                if end >= 0:
                    size = end + len(delimiter)
                    if size > max_frame_bytes:
                        raise _Stop("frame_limit", "protocol frame exceeds byte limit")
                    break
                if len(pending) >= max_frame_bytes:
                    raise _Stop("frame_limit", "protocol frame exceeds byte limit")
                receive()
            wire = bytes(pending[:size])
            del pending[:size]
            body = wire[:-len(delimiter)]
            report["frames"].append({"start_offset": consumed, "end_offset": consumed + size,
                                     "wire_hex": wire.hex()})
            consumed += size

            if body.startswith(done_prefix):
                suffix_size = len(body) - len(done_prefix)
                if len(report["rounds"]) < done_rounds:
                    raise _Stop("premature_completion", "completion arrived before declared rounds")
                if not done_min <= suffix_size <= done_max:
                    raise _Stop("unexpected_frame", "completion suffix does not match declaration")
                report["completion_hex"] = wire.hex()
                report["status"] = "complete"
                break
            if not body.startswith(prefix):
                raise _Stop("unexpected_frame", "undeclared protocol frame")
            rest = body[len(prefix):]
            id_bytes, found, expression = rest.partition(separator)
            if not found or not id_bytes or any(c < 48 or c > 57 for c in id_bytes):
                raise _Stop("unexpected_frame", "question does not match declared grammar")
            round_id = int(id_bytes)
            expected = first + len(report["rounds"]) * step
            if round_id != expected:
                raise _Stop("stale_round", "question ID does not match the next round")
            if suffix:
                if not expression.endswith(suffix):
                    raise _Stop("unexpected_frame", "question suffix does not match declaration")
                expression = expression[:-len(suffix)]
            if len(report["rounds"]) >= max_rounds:
                raise _Stop("round_limit", "round limit reached before completion")
            try:
                answer = solve(expression.decode("ascii"))
                if abs(answer) > max_integer:
                    raise ValueError("answer exceeds declared integer bound")
            except (UnicodeDecodeError, ValueError, ArithmeticError, RecursionError) as exc:
                raise _Stop("expression", f"unsupported or invalid arithmetic: {type(exc).__name__}") from exc
            answer_wire = response_prefix + str(answer).encode("ascii") + response_suffix
            send(answer_wire)
            report["rounds"].append({"id": round_id, "expression": expression.decode("ascii"),
                                     "answer": answer, "question_frame": len(report["frames"]) - 1,
                                     "response_hex": answer_wire.hex()})
    except _Stop as exc:
        report["error"] = exc.code
        warnings.append(str(exc))
    except (OSError, TimeoutError) as exc:
        report["error"] = "timeout" if isinstance(exc, TimeoutError) else "transport_error"
        warnings.append(f"arithmetic service {report['error']}: {type(exc).__name__}")
    except KeyboardInterrupt:
        report["error"] = "interrupted"
        warnings.append("arithmetic service interrupted")
    finally:
        report["pending_hex"] = pending.hex()
        if sock is not None:
            sock.close()
    return report, warnings
