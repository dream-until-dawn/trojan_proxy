"""真实HTTP/TLS检查及受限诊断；任何失败都保留，不用重试把红灯改绿。"""
import hashlib
import http.client
import json
import socket
import ssl
import time
from checks import CheckFailure


class DirectHTTPS(http.client.HTTPSConnection):
    """只改变连接IP，仍以授权域名执行完整证书校验。"""
    def connect(self):
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=5)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)


def response_category(body):
    # 仅输出固定类别；未知正文可能来自误路由的业务，不允许写入诊断文件。
    known = {'访问地址不被允许': 'host_not_allowed', '请求来源不被允许': 'origin_not_allowed'}
    try:
        value = json.loads(body)
        error = value.get('error') if isinstance(value, dict) else None
        return known.get(error, 'other') if isinstance(error, str) else 'other'
    except (ValueError, UnicodeError):
        return 'other'


def check_response(connection, port, path, method, host, expected, results, origin=None):
    """逐端点记录预期与实际状态；不保存响应头中的Cookie或响应正文。"""
    record = {'port': port, 'path': path, 'method': method, 'expected': expected}
    started = time.monotonic()
    headers = {'Host': host}
    if origin: headers.update({'Origin': origin, 'Content-Type': 'application/json'})
    try:
        connection.request(method, path, body='{}' if method == 'POST' else None, headers=headers)
        response = connection.getresponse()
        body = response.read(100001)
        record['actual'] = response.status
        record['response_category'] = response_category(body)
        if len(body) > 100000: raise CheckFailure('http_response_exceeds_budget', dict(record))
        if response.status != expected: raise CheckFailure('unexpected_http_status', dict(record))
        return body, response.getheader('Location'), response.getheader('X-Robots-Tag')
    except CheckFailure:
        raise
    except Exception as error:
        record['exception_type'] = type(error).__name__
        raise CheckFailure('http_request_failed', dict(record)) from None
    finally:
        record['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
        results.append(record)
        connection.close()


def web_checks(domain, admin, vpn, control, results=None):
    results = results if results is not None else []
    for port, path, method, expected in [(control, '/healthz', 'GET', 200), (80, '/', 'GET', 308),
                                         (80, '/robots.txt', 'GET', 200), (443, '/', 'GET', 200),
                                         (admin, '/api/vpn/status', 'POST', 401)]:
        secure = port in (443, admin)
        connection = DirectHTTPS(domain, port, timeout=5) if secure else http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        host = domain + (':' + str(admin) if port == admin else '')
        if port == control: host = '127.0.0.1:' + str(control)
        body, location, robots = check_response(connection, port, path, method, host, expected, results,
                                                'https://' + domain + ':' + str(admin) if method == 'POST' else None)
        details = {'port': port, 'path': path, 'method': method}
        if port == 80 and path == '/' and location != 'https://' + domain + '/': raise CheckFailure('wrong_http_redirect', details)
        if path == '/robots.txt' and b'Disallow: /' not in body: raise CheckFailure('robots_missing', details)
        if port == 443 and (not robots or domain.encode() not in body): raise CheckFailure('welcome_or_noindex_missing', details)
    fingerprints = {}
    for port in (443, admin, vpn):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=domain) as tls:
                    fingerprints[str(port)] = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        except Exception as error:
            raise CheckFailure('tls_validation_failed', {'port': port, 'exception_type': type(error).__name__}) from None
    if len(set(fingerprints.values())) != 1: raise CheckFailure('certificate_publication_not_converged')
    return fingerprints
