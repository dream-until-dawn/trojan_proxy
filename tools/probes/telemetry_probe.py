"""编译固定引擎源码中的计量探针，在无外网、非root Linux容器验证。"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
binary = root / '.work/telemetry-probe.test'
name = 'trojan-telemetry-probe-' + uuid.uuid4().hex[:12]
report = {'passed': False, 'scope': 'outbound adapter probe, production collection is not enabled'}
try:
    build = subprocess.run(['go', 'test', '-C', str(root / 'engines/trojan'), '-c', '-tags', 'integration', '-o', str(binary)],
                           env=dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=120)
    if build.returncode:
        raise RuntimeError(build.stdout[-2000:])
    report['probe_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    image = subprocess.run(['docker', 'image', 'inspect', 'trojan-control:m6', '--format', '{{.Id}}'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8', check=True, timeout=10).stdout.strip()
    report['base_image'] = image
    result = subprocess.run(['docker', 'run', '--rm', '--name', name, '--network', 'none',
                             '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL',
                             '--security-opt', 'no-new-privileges', '--memory', '128m', '--cpus', '1',
                             '--tmpfs', '/tmp:uid=10001,gid=10001,mode=0700', '-v', str(binary)+':/probe:ro',
                             '--entrypoint', '/probe', image, '-test.run=TestActualOutboundTelemetryTCPFallbackAndUDP',
                             '-test.v', '-test.timeout=30s'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding='utf-8', timeout=45)
    report['output'] = result.stdout
    if result.returncode:
        raise RuntimeError('Actual outbound telemetry probe failed')
    report['passed'] = True
except Exception as error:
    report['error'] = str(error)
finally:
    # 唯一随机名字只属于本脚本，不清理其他容器或镜像。
    subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
print(json.dumps(report, ensure_ascii=False, indent=2))
raise SystemExit(0 if report['passed'] else 1)
