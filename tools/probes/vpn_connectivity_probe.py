"""有界只读诊断：凭据仅在服务器内存使用，不输出原始配置或秘密。"""
import hashlib
import ipaddress
import json
import socket
import ssl
import struct
import subprocess


def docker(args):
    result = subprocess.run(['docker'] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15)
    if result.returncode:
        raise RuntimeError('Docker diagnostic command failed')
    return result.stdout


def handshake(address, port, domain):
    with socket.create_connection((address, port), timeout=7) as raw:
        return ssl.create_default_context().wrap_socket(raw, server_hostname=domain)


def check(operation):
    try:
        return operation()
    except Exception as error:
        # 异常仅包含网络错误，不包含配置、认证信息或原始子进程输出。
        return {'error_type': type(error).__name__, 'message': str(error)[:200]}


ids = docker(['ps', '-q', '--filter', 'label=com.docker.compose.project=trojan-refactor',
              '--filter', 'label=com.docker.compose.service=vpn-runner']).decode().split()
if len(ids) != 1:
    raise RuntimeError('Expected exactly one owned VPN runner')
container = json.loads(docker(['inspect', ids[0]]))[0]
if not container['State']['Running']:
    raise RuntimeError('Runner is not running')
# 临时运行 JSON 由 runner 专有 tmpfs 保存；禁止将它写入诊断输出或本地文件。
config = json.loads(docker(['exec', ids[0], 'cat', '/run/vpn/private/config.json']))
inbound = config['inbounds'][0]
port = inbound['listen_port']
with open('/opt/trojan-proxy-refactor/admin.proxy.example.json') as stream:
    deployment = json.load(stream)
domain = deployment['domain']
report = {'port': port, 'runner_started': container['State']['StartedAt'], 'checks': {}}


def tls_local():
    with handshake('127.0.0.1', port, domain) as connection:
        return {'tls': connection.version(), 'certificate_sha256':
                hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()}


def http_request(address, via_trojan):
    host = 'www.google.com'
    if via_trojan:
        connection = handshake('127.0.0.1', port, domain)
        # Trojan 标准请求：认证散列、CONNECT、目标地址和端口。
        target = host.encode() if address is None else ipaddress.ip_address(address).packed
        destination = (b'\x03' + bytes([len(target)]) + target) if address is None else b'\x01' + target
        password = inbound['users'][0]['password']
        connection.sendall(hashlib.sha224(password.encode()).hexdigest().encode() + b'\r\n' +
                           b'\x01' + destination + struct.pack('!H', 80) + b'\r\n')
    else:
        connection = socket.create_connection((host, 80), timeout=7)
    with connection:
        connection.settimeout(10)
        connection.sendall(b'GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n')
        first = connection.recv(2048).split(b'\r\n', 1)[0]
        return {'status_line': first.decode('ascii', errors='replace')[:120]}


report['checks']['local_tls'] = check(tls_local)
report['checks']['direct_google_http'] = check(lambda: http_request(None, False))
report['checks']['trojan_google_domain_http'] = check(lambda: http_request(None, True))
addresses = check(lambda: sorted(set(item[4][0] for item in socket.getaddrinfo('www.google.com', 80, socket.AF_INET))))
report['checks']['google_ipv4_dns'] = addresses
if isinstance(addresses, list) and addresses:
    report['checks']['trojan_google_ip_http'] = check(lambda: http_request(addresses[0], True))


def google_https(wrong_password=False):
    host = b'www.google.com'
    with handshake('127.0.0.1', port, domain) as tunnel:
        tunnel.settimeout(8)
        password = inbound['users'][0]['password'] + ('-invalid' if wrong_password else '')
        tunnel.sendall(hashlib.sha224(password.encode()).hexdigest().encode() + b'\r\n' +
                       b'\x01\x03' + bytes([len(host)]) + host + struct.pack('!H', 443) + b'\r\n')
        # 内层 Google TLS 使用系统信任库，MemoryBIO 避免把外层 TLS 当作明文 socket。
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.create_default_context()
        context.set_alpn_protocols(['http/1.1'])
        inner = context.wrap_bio(incoming, outgoing, server_hostname=host.decode())

        def flush():
            while outgoing.pending:
                tunnel.sendall(outgoing.read())

        def perform(operation):
            for _ in range(64):
                try:
                    result = operation()
                    flush()
                    return result
                except ssl.SSLWantReadError:
                    flush()
                    packet = tunnel.recv(16384)
                    if not packet:
                        raise EOFError('Tunnel closed before inner TLS response')
                    incoming.write(packet)
            raise RuntimeError('Inner TLS iteration budget exceeded')

        perform(inner.do_handshake)
        request = b'GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n'
        sent = 0
        while sent < len(request):
            sent += perform(lambda: inner.write(request[sent:]))
        response = perform(lambda: inner.read(2048))
        return {'status_line': response.split(b'\r\n', 1)[0].decode('ascii', errors='replace')[:120],
                'inner_tls_verified': True}


report['checks']['trojan_google_https'] = check(google_https)
negative = check(lambda: google_https(True))
report['checks']['wrong_password'] = {'rejected': 'error_type' in negative,
                                      'error_type': negative.get('error_type')}
print(json.dumps(report, ensure_ascii=False, indent=2))
