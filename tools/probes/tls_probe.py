#!/usr/bin/env python3
"""在隔离高端口验证 TLS 交接、证书轮换及错误密钥保护。"""
import copy
import hashlib
import json
import os
import socket
import ssl
import tempfile
import time
import uuid

from gateway_probe import command, free_port, request, running_snapshot


def certificate(directory, name):
    """生成只用于探针的自签名证书；使用配置文件兼容旧 OpenSSL。"""
    prefix = os.path.join(directory, name)
    with open(prefix + '.cnf', 'w') as output:
        output.write('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n'
                     '[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost\n'
                     'basicConstraints=critical,CA:TRUE\n')
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-config', prefix + '.cnf', '-keyout', prefix + '.key', '-out', prefix + '.crt'])
    return prefix


def handshake(port, trust):
    """正常验证服务器身份和信任链，返回实际证书指纹。"""
    context = ssl.create_default_context(cafile=trust)
    with socket.create_connection(('127.0.0.1', port), timeout=4) as raw:
        with context.wrap_socket(raw, server_hostname='localhost') as conn:
            return hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()


def main():
    before = running_snapshot()
    report = {'checks': {}, 'limitations': ['未验证真实80/443、ACME自动签发、Trojan及跨组件事务。']}
    container = None
    guard = None
    try:
        with tempfile.TemporaryDirectory(prefix='trojan-tls-') as directory:
            first, second = certificate(directory, 'first'), certificate(directory, 'second')
            admin, tls = free_port(), free_port()
            guard = socket.socket()
            guard.bind(('127.0.0.1', tls))
            guard.listen(1)
            image = 'caddy@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9'
            container = command(['docker', 'run', '-d', '--name', 'trojan-tls-probe-' + uuid.uuid4().hex[:10],
                '--network', 'host', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                '--memory', '128m', '--cpus', '0.5', '--pids-limit', '128',
                '--tmpfs', '/config', '--tmpfs', '/data', '--tmpfs', '/tmp',
                '-v', directory + ':/certs:ro', '-e', 'CADDY_ADMIN=127.0.0.1:{}'.format(admin), image, 'caddy', 'run'])
            for attempt in range(50):
                try:
                    if request(admin, '/config/')[0] == 200:
                        break
                except OSError:
                    pass
                time.sleep(.2)
            config = {'admin': {'listen': '127.0.0.1:{}'.format(admin)}, 'apps': {
                'tls': {'certificates': {'load_files': [{'certificate': '/certs/first.crt', 'key': '/certs/first.key'}]}},
                'http': {'servers': {'secure': {'listen': ['127.0.0.1:{}'.format(tls)],
                    'automatic_https': {'disable': True}, 'tls_connection_policies': [{}],
                    'routes': [{'handle': [{'handler': 'static_response', 'body': 'tls-ok'}]}]}}}}}
            status, body = request(admin, '/load', config)
            assert status >= 400 and 'address already in use' in body, '保留监听未阻止抢占'
            report['checks']['guard_blocks_tls_bind'] = 'PASS'
            guard.close()
            guard = None
            assert request(admin, '/load', config)[0] == 200, '释放后TLS启动失败'
            old = handshake(tls, first + '.crt')
            report['checks']['guard_to_verified_tls'] = 'PASS'
            rotated = copy.deepcopy(config)
            rotated['apps']['tls']['certificates']['load_files'] = [
                {'certificate': '/certs/second.crt', 'key': '/certs/second.key'}]
            assert request(admin, '/load', rotated)[0] == 200
            new = handshake(tls, second + '.crt')
            assert old != new, '实际握手证书未轮换'
            report['checks']['certificate_rotation_fingerprint_changed'] = 'PASS'
            try:
                handshake(tls, first + '.crt')
                raise AssertionError('错误信任根被接受')
            except ssl.SSLError:
                report['checks']['untrusted_certificate_rejected'] = 'PASS'
            broken = copy.deepcopy(rotated)
            broken['apps']['tls']['certificates']['load_files'][0]['key'] = '/certs/first.key'
            status, body = request(admin, '/load', broken)
            assert status >= 400 and 'private key' in body.lower(), '未因私钥不匹配拒绝'
            assert handshake(tls, second + '.crt') == new, '坏私钥破坏有效TLS'
            report['checks']['mismatched_key_rejected_previous_tls_live'] = 'PASS'
            report['fingerprints'] = {'before': old, 'after': new}
    except Exception as error:
        report['error'] = str(error)
    finally:
        if guard:
            guard.close()
        if container:
            command(['docker', 'rm', '-f', container])
        after = running_snapshot()
        report['existing_running_containers_unchanged'] = all(after.get(k) == v for k,v in before.items())
    report['passed'] = len(report['checks']) == 5 and 'error' not in report and report['existing_running_containers_unchanged']
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
