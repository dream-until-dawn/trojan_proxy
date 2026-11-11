#!/usr/bin/env python3
"""在 Linux Docker 主机执行有界网关探针；仅创建自有回环监听资源。"""

import argparse
import copy
import http.server
import json
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid


def command(args, timeout=30):
    """执行固定参数命令，失败保留可诊断信息；不经 shell。"""
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('{}: {}'.format(args[:2], result.stderr[-1200:]))
    return result.stdout.strip()


def request(port, path='/', payload=None):
    """显式绕开系统代理，仅向当前主机回环地址发出请求。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    data = None if payload is None else json.dumps(payload).encode('utf-8')
    req = urllib.request.Request('http://127.0.0.1:{}{}'.format(port, path),
                                 data=data, headers={'Content-Type': 'application/json'})
    try:
        with opener.open(req, timeout=3) as response:
            return response.status, response.read().decode('utf-8')
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode('utf-8')


def free_port():
    """分配探针候选端口；最终容器 bind 仍可能失败，届时清理退出。"""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def running_snapshot():
    """只比较原有运行容器的身份与启动时间，不输出环境变量。"""
    ids = command(['docker', 'ps', '-q']).split()
    if not ids:
        return {}
    items = json.loads(command(['docker', 'inspect'] + ids))
    return {item['Id']: item['State']['StartedAt'] for item in items}


class Upstream(http.server.BaseHTTPRequestHandler):
    """宿主机回环上的 HTTP 哨兵，用来证明 host 网络可访问真实上游。"""

    def do_GET(self):
        body = b'loopback-upstream-ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def probe(image, pull=False):
    """验证路由应用与拒绝行为；任何断言失败都使探针失败。"""
    report = {'checks': {}, 'limitations': [
        '仅验证回环 HTTP 与 Caddy 单组件配置应用，未验证真实 80/443。',
        '未验证 ACME、跨组件事务、证书发布、鉴权或 Trojan。']}
    before = running_snapshot()
    name = 'trojan-design-probe-' + uuid.uuid4().hex[:12]
    upstream = None
    container_id = None
    held = None
    try:
        if pull:
            command(['docker', 'pull', image], timeout=180)
        meta = json.loads(command(['docker', 'image', 'inspect', image]))[0]
        report['image_id'] = meta['Id']
        report['repo_digests'] = meta.get('RepoDigests', [])
        upstream = Server(('127.0.0.1', 0), Upstream)
        threading.Thread(target=upstream.serve_forever, daemon=True).start()
        admin, first, second = free_port(), free_port(), free_port()
        assert len({admin, first, second, upstream.server_port}) == 4, '候选端口重复'
        container_id = command([
            'docker', 'run', '-d', '--name', name, '--network', 'host',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--memory', '128m', '--cpus', '0.5', '--pids-limit', '128',
            '--tmpfs', '/config', '--tmpfs', '/data', '--tmpfs', '/tmp',
            '-e', 'CADDY_ADMIN=127.0.0.1:{}'.format(admin),
            meta['Id'], 'caddy', 'run'])
        deadline = time.monotonic() + 15
        while True:
            try:
                if request(admin, '/config/')[0] == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() > deadline:
                raise RuntimeError('Caddy 管理接口启动超时')
            time.sleep(0.2)
        config = {'admin': {'listen': '127.0.0.1:{}'.format(admin)}, 'apps': {
            'http': {'servers': {'primary': {
                'listen': ['127.0.0.1:{}'.format(first)],
                'automatic_https': {'disable': True},
                'routes': [{'handle': [{'handler': 'reverse_proxy', 'upstreams': [
                    {'dial': '127.0.0.1:{}'.format(upstream.server_port)}]}]}]
            }}}}}
        assert request(admin, '/load', config)[0] == 200, '首次配置被拒'
        assert request(first) == (200, 'loopback-upstream-ok'), '宿主机回环反代失败'
        report['checks']['host_loopback_proxy'] = 'PASS'
        config['apps']['http']['servers']['extra'] = {
            'listen': ['127.0.0.1:{}'.format(second)],
            'automatic_https': {'disable': True},
            'routes': [{'handle': [{'handler': 'static_response', 'body': 'dynamic-port-ok'}]}]}
        assert request(admin, '/load', config)[0] == 200, '动态端口应用失败'
        assert request(second) == (200, 'dynamic-port-ok'), '动态端口不可访问'
        report['checks']['dynamic_listener_without_recreate'] = 'PASS'
        invalid = copy.deepcopy(config)
        invalid['apps']['http']['servers']['extra']['routes'][0]['handle'][0]['handler'] = 'probe_nonexistent_handler'
        code, body = request(admin, '/load', invalid)
        assert code >= 400 and 'probe_nonexistent_handler' in body, '未以指定非法模块原因拒绝'
        assert request(first) == (200, 'loopback-upstream-ok'), '坏配置破坏原反代'
        assert request(second) == (200, 'dynamic-port-ok'), '坏配置破坏额外监听'
        report['checks']['invalid_handler_rejected_old_routes_live'] = 'PASS'
        held = socket.socket()
        held.bind(('127.0.0.1', 0))
        held.listen(1)
        conflict = copy.deepcopy(config)
        conflict['apps']['http']['servers']['conflict'] = {
            'listen': ['127.0.0.1:{}'.format(held.getsockname()[1])],
            'automatic_https': {'disable': True}}
        code, body = request(admin, '/load', conflict)
        assert code >= 400 and 'address already in use' in body, '未按端口冲突原因拒绝'
        assert request(first) == (200, 'loopback-upstream-ok'), '冲突破坏原反代'
        assert request(second) == (200, 'dynamic-port-ok'), '冲突破坏额外监听'
        report['checks']['occupied_port_rejected_old_routes_live'] = 'PASS'
        report['version'] = command(['docker', 'exec', container_id, 'caddy', 'version'])
    except Exception as error:
        report['error'] = str(error)
    finally:
        if held:
            held.close()
        if container_id:
            try:
                command(['docker', 'rm', '-f', container_id])
                report['probe_container_removed'] = True
            except Exception as error:
                report['cleanup_error'] = str(error)
        if upstream:
            upstream.shutdown()
            upstream.server_close()
        after = running_snapshot()
        report['existing_running_containers_unchanged'] = all(
            after.get(container) == started for container, started in before.items())
        report['existing_running_container_count'] = len(before)
    report['passed'] = (len(report['checks']) == 4 and 'error' not in report
                        and report.get('probe_container_removed', False)
                        and report['existing_running_containers_unchanged'])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='caddy:2-alpine')
    parser.add_argument('--pull', action='store_true')
    args = parser.parse_args()
    sys.exit(probe(args.image, args.pull))
