#!/usr/bin/env python3
"""Bounded local receiver for an explicitly authorized chatbot fetch-tool probe."""

import argparse
import base64
import hashlib
import json
import os
import stat
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
    parser.add_argument('--response-file', help='bounded page body to serve to one declared fetch tool')
    parser.add_argument('--response-path', help='exact GET path for the served page')
    parser.add_argument('--content-type', choices=('text/plain', 'text/html', 'application/json'), default='text/plain')
    args = parser.parse_args(argv)
    if (not 0 <= args.port <= 65535 or not 1 <= args.max_requests <= 10 or not 0 < args.duration <= 300 or
            args.bind not in ('127.0.0.1', 'localhost') and not args.allow_public_bind):
        parser.error('invalid limits or non-loopback bind without --allow-public-bind')
    response_body = None
    if args.response_file is not None:
        if (not isinstance(args.response_path, str) or not args.response_path.startswith('/') or
                args.response_path.startswith('//') or '#' in args.response_path or
                any(ord(c) < 33 for c in args.response_path)):
            parser.error('--response-file needs one exact absolute --response-path, optionally with a query')
        try:
            path = Path(os.path.abspath(args.response_file))
            parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
            try:
                for part in path.parts[1:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=parent)
                    os.close(parent)
                    parent = child
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                     dir_fd=parent)
            finally:
                os.close(parent)
            with os.fdopen(descriptor, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    parser.error('response file must be a regular file')
                response_body = stream.read(64 * 1024 + 1)
        except OSError as error:
            parser.error(f'cannot read response file: {error.strerror}')
        if len(response_body) > 64 * 1024:
            parser.error('response file exceeds 64 KiB')
    elif args.response_path is not None:
        parser.error('--response-path needs --response-file')
    run = Path(args.runs_root or '.autosolve/runs') / f'chat-callback-{uuid.uuid4().hex[:12]}'
    run.mkdir(parents=True, mode=0o700)
    log = run / 'requests.jsonl'
    log.touch(mode=0o600)
    if response_body is not None:
        snapshot = run / 'response.bin'
        snapshot.write_bytes(response_body)
        snapshot.chmod(0o600)
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
            if response_body is not None and (self.command != 'GET' or self.path != args.response_path):
                self.send_error(404)
                return
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
            if response_body is not None:
                record['response_sha256'] = hashlib.sha256(response_body).hexdigest()
                record['response_bytes'] = len(response_body)
            line = json.dumps(record) + '\n'
            if log.stat().st_size + len(line.encode()) > 1024 * 1024:
                self.send_error(507)
                return
            with log.open('a') as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
            count += 1
            self.send_response(200 if response_body is not None else 204)
            if response_body is not None:
                self.send_header('Content-Type', args.content_type)
                self.send_header('Content-Length', str(len(response_body)))
            self.end_headers()
            if response_body is not None:
                try:
                    self.wfile.write(response_body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

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
