"""Replay only declared, authorized HTTP workflows and compare observed state."""

import base64
import binascii
import hashlib
import http.cookiejar
import json
import re
import time
import urllib.error
import urllib.request

from .web_static import _origin


_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_RELATIONS = {'same_status', 'different_status', 'same_body', 'different_body',
              'same_response', 'different_response'}
_FORBIDDEN_HEADERS = {'host', 'content-length', 'transfer-encoding', 'connection',
                      'proxy-authorization', 'proxy-connection', 'upgrade'}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def _cookie_state(jar):
    state = sorted((cookie.domain, cookie.path, cookie.name, cookie.value)
                   for cookie in jar)
    return hashlib.sha256(json.dumps(state, separators=(',', ':')).encode()).hexdigest()


def _selector(value, steps):
    if (type(value) is not dict or set(value) != {'role', 'step'} or
            type(value.get('role')) is not str or type(value.get('step')) is not str or
            (value.get('role'), value.get('step')) not in steps):
        raise ValueError('invariant selector must name a supplied role and step')
    return value['role'], value['step']


def _comparison(value, steps, *, baseline=False):
    allowed = {'left', 'right', 'relation'}
    if type(value) is not dict or set(value) - (allowed if baseline else allowed | {'baselines'}) or not allowed <= set(value):
        raise ValueError('invalid workflow comparison')
    relation = value['relation']
    if type(relation) is not str or relation not in _RELATIONS:
        raise ValueError('unsupported workflow relation')
    return {'left': _selector(value['left'], steps),
            'right': _selector(value['right'], steps), 'relation': relation}


def _validated(fixtures, origin, max_requests):
    _origin(origin)
    if type(fixtures) is not dict or set(fixtures) != {'expected_invariant', 'workflows'}:
        raise ValueError('workflow fixture needs two workflows and an expected invariant')
    workflows = fixtures['workflows']
    if type(workflows) is not list or len(workflows) != 2:
        raise ValueError('workflow fixture needs exactly two roles')
    steps = {}
    count = 0
    for workflow in workflows:
        if type(workflow) is not dict or set(workflow) != {'role', 'steps'}:
            raise ValueError('workflow must have a role and declared steps')
        role, requests = workflow['role'], workflow['steps']
        if (type(role) is not str or not 0 < len(role) <= 64 or
                type(requests) is not list or not 1 <= len(requests) <= 4):
            raise ValueError('invalid role or workflow step count')
        if any(key[0] == role for key in steps):
            raise ValueError('workflow roles must be unique')
        count += len(requests)
        for request in requests:
            if type(request) is not dict or set(request) - {
                    'id', 'method', 'path', 'headers', 'body_b64', 'safe_to_replay'}:
                raise ValueError('invalid request fields')
            step_id, method, path = request.get('id'), request.get('method'), request.get('path')
            if (type(step_id) is not str or not 0 < len(step_id) <= 64 or
                    (role, step_id) in steps or method not in
                    ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE') or
                    request.get('safe_to_replay') is not True):
                raise ValueError('every unique workflow step must be explicitly safe to replay')
            if (type(path) is not str or not path.startswith('/') or path.startswith('//') or
                    len(path) > 2048 or '\\' in path or '#' in path or
                    any(ord(char) < 33 or ord(char) > 126 for char in path)):
                raise ValueError('request path must be one bounded same-origin path')
            headers = request.get('headers', {})
            if (type(headers) is not dict or len(headers) > 32 or any(
                    type(name) is not str or not _TOKEN.fullmatch(name) or
                    name.lower() in _FORBIDDEN_HEADERS or type(value) is not str or
                    len(value) > 4096 or any(ord(char) < 32 or ord(char) > 126 for char in value)
                    for name, value in headers.items())):
                raise ValueError('request headers must be bounded and cannot override transport')
            body = request.get('body_b64', '')
            if type(body) is not str or len(body) > 22000:
                raise ValueError('request body exceeds 16 KiB')
            try:
                decoded = base64.b64decode(body, validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError('request body must be base64') from error
            if len(decoded) > 16 * 1024 or (method in ('GET', 'HEAD') and decoded):
                raise ValueError('request body exceeds 16 KiB or is invalid for method')
            steps[role, step_id] = decoded
    if count > max_requests:
        raise ValueError('workflow exceeds request cap')
    invariant = fixtures['expected_invariant']
    comparison = _comparison(invariant, steps)
    baselines = invariant.get('baselines', [])
    if type(baselines) is not list or len(baselines) > 2:
        raise ValueError('at most two baseline comparisons are allowed')
    comparison['baselines'] = [_comparison(item, steps, baseline=True) for item in baselines]
    return workflows, steps, comparison


def _holds(comparison, responses):
    left = responses[comparison['left']]
    right = responses[comparison['right']]
    relation = comparison['relation']
    if 'error' in left or 'error' in right:
        return None
    if (left['truncated'] or right['truncated']) and ('body' in relation or 'response' in relation):
        return None
    if (left['headers_truncated'] or right['headers_truncated']) and 'response' in relation:
        return None
    if 'status' in relation:
        same = left['status'] == right['status']
    elif 'body' in relation:
        same = left['body_sha256'] == right['body_sha256']
    else:
        def fields(row):
            grouped = {}
            for name, value in row['headers']:
                grouped.setdefault(name.lower(), []).append(value)
            return row['status'], grouped, row['body_sha256']

        same = fields(left) == fields(right)
    return same if relation.startswith('same_') else not same


def replay_workflows(fixtures: dict, *, origin: str, timeout: float = 5.0,
                     max_requests: int = 8, max_response_bytes: int = 64 * 1024,
                     rate: float = 5.0
                     ) -> tuple[dict, list[str]]:
    """Run two declared sessions sequentially; response bytes remain private evidence.

    The caller must isolate this worker and keep fixture/output files private. No
    endpoint discovery, redirect following, racing, or vulnerability inference occurs.
    """
    if (type(timeout) not in (int, float) or not 0 < timeout <= 30 or
            type(max_requests) is not int or not 2 <= max_requests <= 8 or
            type(max_response_bytes) is not int or not 0 < max_response_bytes <= 64 * 1024 or
            type(rate) not in (int, float) or not 0 < rate <= 5):
        raise ValueError('workflow limits must be positive and bounded')
    workflows, _steps, comparison = _validated(fixtures, origin, max_requests)
    deadline = time.monotonic() + timeout
    rows, indexed, warnings = [], {}, []
    last_request = None
    for workflow in workflows:
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPCookieProcessor(jar),
                                             _NoRedirect())
        for item in workflow['steps']:
            # Rate and count limits apply across both role sessions.
            if last_request is not None:
                time.sleep(min(1 / rate, max(0, deadline - time.monotonic())))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                warnings.append('workflow time limit reached')
                break
            role, step_id = workflow['role'], item['id']
            body = base64.b64decode(item.get('body_b64', ''), validate=True)
            request = urllib.request.Request(origin.rstrip('/') + item['path'],
                                             data=body if item['method'] not in ('GET', 'HEAD') else None,
                                             headers=item.get('headers', {}), method=item['method'])
            before = _cookie_state(jar)
            last_request = time.monotonic()
            try:
                try:
                    response = opener.open(request, timeout=remaining)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    payload = response.read(max_response_bytes + 1)
                    headers = list(response.headers.items())
                    headers_truncated = sum(len(name) + len(value) for name, value in headers) > 16 * 1024
                    if headers_truncated:
                        warnings.append('response header byte limit reached')
                        headers = []
                    truncated = len(payload) > max_response_bytes
                    if truncated:
                        warnings.append('response byte limit reached')
                        payload = payload[:max_response_bytes]
                    row = {'role': role, 'step': step_id, 'status': response.status,
                           'headers': headers, 'body_b64': base64.b64encode(payload).decode(),
                           'body_sha256': hashlib.sha256(payload).hexdigest(),
                           'body_length': len(payload), 'truncated': truncated,
                           'headers_truncated': headers_truncated,
                           'cookie_state_before_sha256': before,
                           'cookie_state_after_sha256': _cookie_state(jar)}
            except (OSError, urllib.error.URLError, TimeoutError) as error:
                row = {'role': role, 'step': step_id, 'error': type(error).__name__,
                       'cookie_state_before_sha256': before,
                       'cookie_state_after_sha256': _cookie_state(jar)}
                warnings.append(f'workflow request failed: {type(error).__name__}')
            rows.append(row)
            indexed[role, step_id] = row
            if 'error' in row:
                break
        if warnings and any('request failed' in warning or 'time limit' in warning
                            for warning in warnings):
            break

    def check(item):
        if item['left'] not in indexed or item['right'] not in indexed:
            return None
        return _holds(item, indexed)

    baseline_rows = [{**item, 'holds': check(item)} for item in comparison['baselines']]
    holds = check(comparison)
    if any(row['holds'] is not True for row in baseline_rows):
        assessment = 'inconclusive: unstable baseline'
    elif holds is None:
        assessment = ('inconclusive: truncated response' if any(
            row.get('truncated') or row.get('headers_truncated') for row in rows)
                      else 'inconclusive: incomplete workflow')
    else:
        assessment = 'invariant held' if holds else 'observed deviation'
    return {'assessment': assessment, 'invariant_holds': holds,
            'expected_invariant': comparison, 'baselines': baseline_rows,
            'responses': rows}, warnings
