"""固定官方Node隔离运行真实前端网络正反向及指定破坏；没有外部网络。"""
import json
import os
from pathlib import Path
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
image = os.environ.get('TROJAN_FRONTEND_NODE_IMAGE', 'node:22.13.1-bookworm-slim@sha256:e71b848e62e2c32bf5572b327b032a0da79b6a390bc924cdb827249c81e13a88')
name = 'trojan-frontend-request-' + uuid.uuid4().hex[:10]
try:
    result = subprocess.run(['docker', 'run', '--rm', '--name', name, '--network', 'none', '--read-only',
                             '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', '65532:65532',
                             '--memory', '256m', '--pids-limit', '64', '--mount', 'type=bind,source=' + str(root) + ',target=/workspace,readonly',
                             '--workdir', '/workspace', '--entrypoint', 'node', image, '--experimental-vm-modules',
                             'tools/probes/frontend_auth_probe.mjs'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding='utf-8', timeout=180)
    if result.returncode:
        raise RuntimeError('前端真实网络验证失败\n' + result.stdout[-1500:] + result.stderr[-2500:])
    report = json.loads(result.stdout)
    assert report['passed'] and report['node'] == 'v22.13.1' and len(report['checks']) == 7
    assert report['mutation_failure'] == 'timeout_guard_missing'
    report['runtime_image'] = image
    print(json.dumps(report, ensure_ascii=False, indent=2))
finally:
    # 只清理本脚本的随机命名测试容器，超时也不留下监听或进程。
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
