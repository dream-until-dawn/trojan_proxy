"""真实出站探针的计数及半关闭定向破坏，秘密和用户流量均不参与。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
target = root / '.work/telemetry-mutations' / uuid.uuid4().hex[:10]
cases = [
    ('tcp-counter', 'return wrapConn(conn, network, o.recorder), err', 'return conn, err',
     'TCP exact payload count incorrect', 3),
    ('upload-direction', 'Upload: int64(n)', 'Download: int64(n)',
     'TCP exact payload count incorrect', 2),
    ('half-close', 'func (c *observedConn) CloseWrite() error', 'func (c *observedConn) DisabledCloseWrite() error',
     'telemetry removed TCP half-close', 1),
    ('udp-upload-direction', 'Event{Network: "udp", Target: ip, Upload: int64(n)}', 'Event{Network: "udp", Target: ip, Download: int64(n)}',
     'UDP actual target/payload count incorrect', 1),
]
report = {}
for name, old, new, reason, count in cases:
    directory = target / name
    shutil.copytree(root / 'engines/trojan', directory, copy_function=shutil.copyfile)
    path = directory / 'telemetry/outbound.go'
    source = path.read_text(encoding='utf-8')
    assert source.count(old) == count, (name, source.count(old))
    path.write_text(source.replace(old, new), encoding='utf-8')
    result = subprocess.run(['go', 'test', '-C', str(directory), '-tags', 'integration', '.', '-run', '^TestActualOutboundTelemetryTCPFallbackAndUDP$', '-count=1'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
    assert result.returncode != 0 and reason in result.stdout, (name, result.returncode, result.stdout)
    report[name] = {'passed': True, 'expected_failure': reason}
print(json.dumps({'passed': True, 'mutations': report}, ensure_ascii=False, indent=2))
