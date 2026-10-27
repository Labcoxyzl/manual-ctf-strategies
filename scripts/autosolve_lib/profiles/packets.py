"""Bounded, offline packet evidence from the approved local TShark."""

import json
import os
import selectors
import shutil
import subprocess
import time
from pathlib import Path


TSHARK = (shutil.which(os.environ.get('AUTOSOLVE_TSHARK', 'tshark'))
          or os.environ.get('AUTOSOLVE_TSHARK') or '/usr/bin/tshark')
ANALYSIS = (
    "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.spurious_retransmission", "tcp.analysis.out_of_order",
    "tcp.analysis.reused_ports",
)
FIELDS = (
    "frame.number", "frame.protocols", "frame.cap_len", "frame.len",
    "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "eth.src", "eth.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.stream",
    "dns.qry.name", "dns.a", "dns.aaaa", "dns.cname", "dns.txt",
    "http.request.method", "http.host", "http.request.uri", "http.response.code",
    "http.user_agent", "http.content_type",
) + ANALYSIS


def inspect_pcap(path: Path, *, timeout: float, max_output: int) -> tuple[list[dict], list[str]]:
    """Return frame-linked DNS, HTTP, endpoint and TCP evidence without reassembly."""
    if timeout <= 0 or max_output <= 0:
        raise ValueError("packet timeout and output limit must be positive")
    source = str(path.resolve())
    argv = [TSHARK, "-r", source, "-n", "-o", "tcp.try_heuristic_first:TRUE",
            "-T", "ek",
            *(part for field in FIELDS for part in ("-e", field))]
    try:
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        return [], [f"TShark unavailable: {error}"]

    output = bytearray()
    errors = bytearray()
    warnings: list[str] = []
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ, output)
        selector.register(process.stderr, selectors.EVENT_READ, errors)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warnings.append("TShark timed out; packet inventory incomplete")
                break
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                room = max_output - len(output) - len(errors)
                if len(chunk) > room:
                    key.data.extend(chunk[:room])
                    warnings.append("TShark output limit reached; packet inventory incomplete")
                    break
                key.data.extend(chunk)
            if warnings:
                break
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()
        process.stderr.close()

    if process.returncode and not warnings:
        detail = errors.decode("utf-8", "replace").strip().splitlines()
        message = detail[0][:300] if detail else "unknown error"
        if "doesn't support" in message or "not a capture file" in message:
            warnings.append(f"TShark exited {process.returncode}; unsupported capture: {message}")
        else:
            warnings.append(f"TShark exited {process.returncode}; capture may be incomplete: {message}")

    # A killed process may end after a partial JSON line. Keep only complete frames.
    if warnings and not output.endswith(b"\n"):
        output = output[:output.rfind(b"\n") + 1]
    records: list[dict] = []
    try:
        for line in output.splitlines():
            item = json.loads(line)
            if 'index' in item:
                continue
            layers = item.get('layers')
            if not isinstance(layers, dict):
                warnings.append('invalid TShark JSON row; packet inventory incomplete')
                break

            def values(field):
                result = layers.get(field.replace('.', '_'), [])
                if not isinstance(result, list) or any(not isinstance(value, str) for value in result):
                    raise ValueError(f'invalid TShark field {field}')
                return result

            def one(field):
                found = values(field)
                return found[0] if found else ''

            number = int(one('frame.number'))
            protocols = one('frame.protocols').split(':') if one('frame.protocols') else []
            ip_sources, ip_targets = values('ip.src'), values('ip.dst')
            ipv6_sources, ipv6_targets = values('ipv6.src'), values('ipv6.dst')
            source_layers, target_layers = [], []
            ip_index = ipv6_index = 0
            for protocol in protocols:
                if protocol == 'ip' and ip_index < min(len(ip_sources), len(ip_targets)):
                    source_layers.append(ip_sources[ip_index])
                    target_layers.append(ip_targets[ip_index])
                    ip_index += 1
                elif protocol == 'ipv6' and ipv6_index < min(len(ipv6_sources), len(ipv6_targets)):
                    source_layers.append(ipv6_sources[ipv6_index])
                    target_layers.append(ipv6_targets[ipv6_index])
                    ipv6_index += 1
            if ip_index != len(ip_sources) or ipv6_index != len(ipv6_sources):
                warnings.append(f'frame {number}: endpoint layer ordering incomplete')
                source_layers.extend(ip_sources[ip_index:] + ipv6_sources[ipv6_index:])
                target_layers.extend(ip_targets[ip_index:] + ipv6_targets[ipv6_index:])
            if len(source_layers) > 1 or len(target_layers) > 1:
                warnings.append(f'frame {number}: nested IP endpoints; innermost selected and all retained')
            tcp_streams = values('tcp.stream')
            record = {
                "packet": number, "locator": f"frame {number}", "source": source,
                "tool": TSHARK,
                "protocols": protocols,
                "src_address": source_layers[-1] if source_layers else one('eth.src') or None,
                "dst_address": target_layers[-1] if target_layers else one('eth.dst') or None,
                "src_port": int(one('tcp.srcport') or one('udp.srcport') or 0) or None,
                "dst_port": int(one('tcp.dstport') or one('udp.dstport') or 0) or None,
                "tcp_stream": int(tcp_streams[-1]) if tcp_streams else None,
                "captured_length": int(one('frame.cap_len')),
                "wire_length": int(one('frame.len')),
            }
            if len(source_layers) > 1:
                record['src_addresses'] = source_layers
            if len(target_layers) > 1:
                record['dst_addresses'] = target_layers
            if len(tcp_streams) > 1:
                record['tcp_streams'] = [int(value) for value in tcp_streams]
                warnings.append(f'frame {number}: multiple TCP stream identifiers retained')
            dns = {label: values(field) for label, field in (
                ("queries", "dns.qry.name"), ("a", "dns.a"), ("aaaa", "dns.aaaa"),
                ("cname", "dns.cname"), ("txt", "dns.txt")) if values(field)}
            if dns:
                record["dns"] = dns
            http_fields = {label: values(field) for label, field in (
                ("method", "http.request.method"), ("host", "http.host"),
                ("uri", "http.request.uri"), ("status", "http.response.code"),
                ("user_agent", "http.user_agent"), ("content_type", "http.content_type"))
                    if values(field)}
            if http_fields:
                record["http"] = {label: items[0] for label, items in http_fields.items()}
                if any(len(items) > 1 for items in http_fields.values()):
                    record['http_fields'] = http_fields
                    warnings.append(f'frame {number}: multiple HTTP field occurrences retained without pairing')
            flags = [field.removeprefix("tcp.analysis.") for field in ANALYSIS if values(field)]
            if flags:
                record["tcp_analysis"] = flags
            records.append(record)
            if record["captured_length"] < record["wire_length"]:
                warnings.append(f"frame {number}: packet data truncated by capture")
            if "ack_lost_segment" in flags:
                warnings.append(f"frame {number} TCP stream {record['tcp_stream']}: "
                                "ACK acknowledges uncaptured TCP segment; conversation incomplete")
            elif "lost_segment" in flags:
                warnings.append(f"frame {number} TCP stream {record['tcp_stream']}: "
                                "uncaptured TCP segment; conversation incomplete")
    except (json.JSONDecodeError, ValueError, TypeError) as error:
        warnings.append(f"invalid TShark JSON output; packet inventory incomplete: {error}")
    if records and not any(set(record["protocols"]) & {"ip", "ipv6", "tcp", "udp", "dns", "http"}
                           for record in records):
        warnings.append("no supported IP, DNS, HTTP or TCP fields found in capture")
    return records, warnings
