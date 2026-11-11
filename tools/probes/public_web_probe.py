"""公网独立验收标准入口、可信TLS、默认欢迎页及统一爬虫声明。"""
import argparse
import hashlib
import http.client
import json
import socket
import ssl

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--ip', default='47.82.112.245')
parser.add_argument('--domain', default='qin-xin.top')
args = parser.parse_args()
report = {'passed': False, 'checks': {}}


class DirectHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection((args.ip, 443), timeout=8)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=args.domain)
        report['certificate_sha256'] = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()


try:
    for secure, path, host, expected in [(False, '/', args.domain, 308),
                                         (False, '/robots.txt', args.domain, 200),
                                         (True, '/', args.domain, 200),
                                         (True, '/robots.txt', args.domain, 200),
                                         (True, '/', 'wrong.example', 404)]:
        connection = DirectHTTPS(args.domain, timeout=8) if secure else http.client.HTTPConnection(args.ip, 80, timeout=8)
        try:
            connection.request('GET', path, headers={'Host': host})
            response = connection.getresponse()
            body = response.read(100000)
            key = ('HTTPS ' if secure else 'HTTP ') + host + path
            report['checks'][key] = {'status': response.status}
            if response.status != expected:
                raise RuntimeError('公网状态不符合预期: ' + key)
            if secure and not response.getheader('X-Robots-Tag'):
                raise RuntimeError('缺少禁止索引响应头')
            if path == '/robots.txt' and b'Disallow: /' not in body:
                raise RuntimeError('爬虫声明未覆盖全部路径')
            if expected == 308 and response.getheader('Location') != 'https://' + args.domain + '/':
                raise RuntimeError('HTTP跳转目标不符合配置')
            if secure and host == args.domain and path == '/':
                if args.domain.encode() not in body or any(word in body.lower() for word in [b'trojan', b'vpn', b'127.0.0.1', b'18090']):
                    raise RuntimeError('欢迎页内容或隐私边界不符合预期')
                report['checks'][key]['welcome_and_privacy'] = True
        finally:
            connection.close()
    report['passed'] = True
except Exception as error:
    report['error'] = type(error).__name__ + ': ' + str(error)[:200]
print(json.dumps(report, ensure_ascii=False, indent=2))
raise SystemExit(0 if report['passed'] else 1)
