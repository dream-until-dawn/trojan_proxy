#!/usr/bin/env python3
"""本地 Docker 隔离网络内验证 Mihomo → Trojan → HTTP 的真实流量。"""
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import uuid

from gateway_probe import command

SERVER = 'ghcr.io/sagernet/sing-box@sha256:0788ffbddab2c68a99a2dd4780bbc50902f159af6f589df3ee74a8389d278279'
CLIENT = 'metacubex/mihomo@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c'


def main():
    report = {'checks': {}, 'limitations': ['未替代 Clash Verge/Clash Mi GUI 与移动设备实测。', '本探针尚不覆盖 UDP。']}
    prefix = 'trojan-protocol-' + uuid.uuid4().hex[:10]
    network = None
    containers = []
    client = None
    try:
        with tempfile.TemporaryDirectory(prefix='trojan-protocol-') as directory:
            root = Path(directory)
            mount = str(root.resolve()) + ':/probe'
            openssl = json.loads(command(['docker','image','inspect','alpine/openssl:latest']))[0]['Id']
            report['openssl_image_id'] = openssl
            (root/'openssl.cnf').write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=vpn\n[ext]\nsubjectAltName=DNS:vpn\nbasicConstraints=critical,CA:TRUE\n')
            for name in ('trusted','untrusted'):
                command(['docker','run','--rm','--network','none','-v',mount,openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                         '-config','/probe/openssl.cnf','-keyout','/probe/'+name+'.key','-out','/probe/'+name+'.crt'])
            network = command(['docker','network','create',prefix])
            backend_script = ('from http.server import BaseHTTPRequestHandler,HTTPServer\n'
                'class H(BaseHTTPRequestHandler):\n'
                ' def do_GET(self):\n'
                '  self.send_response(200);self.end_headers();self.wfile.write(b"trojan-end-to-end-sentinel")\n'
                'HTTPServer(("0.0.0.0",8000),H).serve_forever()')
            backend = command(['docker','run','-d','--name',prefix+'-backend','--network',network,
                '--memory','64m','--cpus','0.5','python:3.12-slim','python','-c',backend_script])
            containers.append(backend)
            info = json.loads(command(['docker','inspect',backend]))[0]
            backend_ip = next(iter(info['NetworkSettings']['Networks'].values()))['IPAddress']
            server_config = {'inbounds':[{'type':'trojan','listen':'0.0.0.0','listen_port':8443,
                'users':[{'name':'probe','password':'probe-only-password'}],
                'tls':{'enabled':True,'certificate_path':'/probe/trusted.crt','key_path':'/probe/trusted.key'}}],
                'outbounds':[{'type':'direct','tag':'direct'}]}
            (root/'server.json').write_text(json.dumps(server_config))
            command(['docker','run','--rm','--network','none','-v',mount,SERVER,'check','-c','/probe/server.json'])
            server = command(['docker','run','-d','--name',prefix+'-server','--network',network,'--network-alias','vpn',
                '--memory','128m','--cpus','0.5','-v',mount,SERVER,'run','-c','/probe/server.json'])
            containers.append(server)
            report['server_version'] = command(['docker','exec',server,'sing-box','version'])

            def start_client(password, trust):
                config = {'mixed-port':7890,'allow-lan':True,'bind-address':'0.0.0.0','mode':'rule',
                    'proxies':[{'name':'probe','type':'trojan','server':'vpn','port':8443,
                        'password':password,'sni':'vpn','skip-cert-verify':False,'udp':True}],
                    'rules':['MATCH,probe']}
                (root/'client.json').write_text(json.dumps(config))
                command(['docker','run','--rm','--network','none','-v',mount,CLIENT,'-t','-f','/probe/client.json'])
                cid = command(['docker','run','-d','--name',prefix+'-client-'+uuid.uuid4().hex[:6],
                    '--network',network,'--memory','128m','--cpus','0.5','-p','127.0.0.1::7890',
                    '-e','SSL_CERT_FILE=/probe/'+trust+'.crt','-v',mount,CLIENT,'-f','/probe/client.json','-d','/tmp'])
                containers.append(cid)
                port = int(command(['docker','port',cid,'7890/tcp']).rsplit(':',1)[1])
                for attempt in range(50):
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=1):
                            return cid, port
                    except OSError:
                        time.sleep(.2)
                raise RuntimeError('Mihomo 代理端口未就绪')

            def fetch(port):
                conn = http.client.HTTPConnection('127.0.0.1',port,timeout=8)
                try:
                    conn.request('GET','http://{}:8000/'.format(backend_ip))
                    response = conn.getresponse()
                    return response.status, response.read().decode('utf-8')
                finally:
                    conn.close()

            client, port = start_client('probe-only-password','trusted')
            assert fetch(port) == (200,'trojan-end-to-end-sentinel'), '真实代理流量失败'
            report['checks']['mihomo_verified_tls_trojan_http'] = 'PASS'
            report['client_version'] = command(['docker','exec',client,'/mihomo','-v'])
            command(['docker','rm','-f',client]); containers.remove(client); client=None
            for password,trust,key in [('wrong-password','trusted','wrong_password_rejected'),
                                       ('probe-only-password','untrusted','untrusted_server_rejected')]:
                client, port = start_client(password,trust)
                try:
                    response = fetch(port)
                    assert response != (200,'trojan-end-to-end-sentinel'), '非法连接读取到哨兵'
                    assert response[0] >= 400, '非法连接未明确失败'
                except (OSError, http.client.HTTPException):
                    pass
                logs = command(['docker','logs',client])
                if key == 'untrusted_server_rejected':
                    assert 'certificate' in logs.lower(), '未观察到证书拒绝原因'
                report['checks'][key] = 'PASS'
                command(['docker','rm','-f',client]); containers.remove(client); client=None
    except Exception as error:
        report['error'] = str(error)
        if client:
            report['client_logs'] = command(['docker','logs',client])[-3000:]
    finally:
        for cid in reversed(containers):
            command(['docker','rm','-f',cid])
        if network:
            command(['docker','network','rm',network])
    report['passed'] = len(report['checks']) == 3 and 'error' not in report
    print(json.dumps(report,ensure_ascii=False,indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
