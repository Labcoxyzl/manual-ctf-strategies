#!/usr/bin/env python3
"""Bounded local receiver for an explicitly authorized chatbot fetch-tool probe."""

import argparse
import base64
import json
import os
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--max-requests', type=int, default=1)
    parser.add_argument('--duration', type=float, default=60)
    parser.add_argument('--runs-root')
    parser.add_argument('--allow-public-bind', action='store_true')
    args = parser.parse_args(argv)
    if (not 0 <= args.port <= 65535 or not 1 <= args.max_requests <= 10 or not 0 < args.duration <= 300 or
            args.bind not in ('127.0.0.1', 'localhost') and not args.allow_public_bind):
        parser.error('invalid limits or non-loopback bind without --allow-public-bind')
    run = Path(args.runs_root or '.autosolve/runs') / f'chat-callback-{uuid.uuid4().hex[:12]}'
    run.mkdir(parents=True, mode=0o700)
    log = run / 'requests.jsonl'
    log.touch(mode=0o600)
    count = 0

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            self.capture()

        def do_POST(self):
            self.capture()

        def do_PUT(self):
            self.capture()

        def capture(self):
            nonlocal count
            try:
                length = int(self.headers.get('Content-Length', '0'))
            except ValueError:
                self.send_error(400)
                return
            if length < 0 or length > 64 * 1024:
                self.send_error(413)
                return
            self.connection.settimeout(5)
            try:
                body = self.rfile.read(length)
            except TimeoutError:
                self.send_error(408)
                return
            record = {'at': time.time(), 'method': self.command, 'path': self.path,
                      'headers': dict(self.headers), 'body_b64': base64.b64encode(body).decode()}
            line = json.dumps(record) + '\n'
            if log.stat().st_size + len(line.encode()) > 1024 * 1024:
                self.send_error(507)
                return
            with log.open('a') as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            count += 1
            self.send_response(204)
            self.end_headers()

    class BoundedHTTPServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address

    with BoundedHTTPServer((args.bind, args.port), Handler) as server:
        print(json.dumps({'status': 'listening', 'origin': f'http://{args.bind}:{server.server_port}',
                          'run': str(run)}), flush=True)
        deadline = time.monotonic() + args.duration
        while count < args.max_requests and time.monotonic() < deadline:
            server.timeout = min(1, max(.01, deadline - time.monotonic()))
            server.handle_request()
    print(json.dumps({'status': 'complete' if count >= args.max_requests else 'partial',
                      'requests': count, 'transcript': str(log)}))
    return 0 if count >= args.max_requests else 3


if __name__ == '__main__':
    raise SystemExit(main())
