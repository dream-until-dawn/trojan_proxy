"""多域观察清单与逐域检查；保留域名维度，不把同路径请求混为一个端点。"""
import hashlib
import http.client
import re
import socket
import ssl
from checks import CheckFailure
from http_checks import DirectHTTPS, check_response, validate_https_routes


def validate_domains(specs, admin_domain=None):
    """只允许显式ASCII域名及有限GET路径，不接受通配、查询参数或凭据。"""
    if not isinstance(specs, list) or len(specs) > 20: raise CheckFailure('invalid_domain_probe')
    seen = set()
    for spec in specs:
        if not isinstance(spec, dict) or set(spec) != {'domain', 'routes'}: raise CheckFailure('invalid_domain_probe')
        domain = spec['domain']
        if not isinstance(domain, str) or len(domain) > 253 or '.' not in domain: raise CheckFailure('invalid_domain_probe')
        if any(not re.fullmatch('[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in domain.split('.')): raise CheckFailure('invalid_domain_probe')
        if domain in seen: raise CheckFailure('duplicate_domain_probe')
        seen.add(domain)
        if not spec['routes']: raise CheckFailure('empty_domain_probe')
        validate_https_routes(spec['routes'])
        if any(route['port'] != 443 for route in spec['routes']): raise CheckFailure('domain_probe_requires_443')
    if admin_domain and admin_domain not in seen: raise CheckFailure('admin_domain_probe_missing')
    return specs


def required_domain_http(specs):
    required = {}
    for spec in validate_domains(specs):
        domain = spec['domain']
        required[(domain, 80, '/', 'GET')] = 308
        required[(domain, 80, '/robots.txt', 'GET')] = 200
        required[(domain, 443, '/robots.txt', 'GET')] = 200
        for route in spec['routes']: required[(domain, 443, route['path'], 'GET')] = route['expected']
    return required


def domain_checks(specs, results):
    """直接连接本机入口，按真实SNI/Host校验可信证书；不重试、不保留正文。"""
    fingerprints = {}
    for (domain, port, path, method), expected in required_domain_http(specs).items():
        connection = DirectHTTPS(domain, port, timeout=5) if port == 443 else http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            body, location, robots = check_response(connection, port, path, method, domain, expected, results)
        except CheckFailure as error:
            error.details['domain'] = domain
            raise
        finally:
            # check_response在成功、状态错误与连接异常时均追加且只追加一条。
            results[-1]['domain'] = domain
        details = {'domain': domain, 'port': port, 'path': path}
        if port == 80 and path == '/' and location != 'https://' + domain + '/': raise CheckFailure('wrong_domain_redirect', details)
        if path == '/robots.txt' and b'Disallow: /' not in body: raise CheckFailure('domain_robots_missing', details)
        if port == 443 and not robots: raise CheckFailure('domain_noindex_missing', details)
    for spec in specs:
        domain = spec['domain']
        try:
            with socket.create_connection(('127.0.0.1', 443), timeout=5) as raw:
                with ssl.create_default_context().wrap_socket(raw, server_hostname=domain) as tls:
                    fingerprints[domain] = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        except Exception as error:
            raise CheckFailure('domain_tls_validation_failed', {'domain': domain, 'exception_type': type(error).__name__}) from None
    return fingerprints
