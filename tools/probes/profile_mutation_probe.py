"""运行参数的编译、导出、端口与自身地址保护定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
target = root / '.work/profile-mutations' / uuid.uuid4().hex[:10]
cases = [
    ('compile', 'vpn/trojan.go', 's, err = EffectiveSettings(s, d)', '_, err = EffectiveSettings(s, d)',
     'runtime profile ignored or removed protected address', 0),
    ('export', 'vpn/trojan.go', 's, err = EffectiveSettings(s, d)', '_, err = EffectiveSettings(s, d)',
     'export diverged from runtime profile', 1),
    ('protected-address', 'vpn/profile.go', 'for _, address := range base.OwnAddresses {', 'for _, address := range []netip.Addr{} {',
     'runtime profile ignored or removed protected address', 0),
    ('reserved-port', 'vpn/profile.go', 'if p.Port == port || p.AdminPort == port {', 'if false && (p.Port == port || p.AdminPort == port) {',
     'runtime profile accepted protected port', 0),
]
report = {}
for name, filename, old, new, reason, occurrence in cases:
    directory = target / name
    shutil.copytree(root / 'internal', directory / 'internal')
    for module in ('go.mod', 'go.sum'):
        shutil.copyfile(root / module, directory / module)
    path = directory / 'internal' / filename
    source = path.read_text(encoding='utf-8')
    positions = [i for i in range(len(source)) if source.startswith(old, i)]
    assert len(positions) == (2 if filename == 'vpn/trojan.go' else 1)
    position = positions[occurrence]
    path.write_text(source[:position] + new + source[position + len(old):], encoding='utf-8')
    result = subprocess.run(['go', 'test', '-C', str(directory), './internal/vpn', '-run', '^TestRuntimeProfileCompileExportAndDeploymentGuards$', '-count=1'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
    assert result.returncode != 0 and reason in result.stdout, (name, result.returncode, result.stdout)
    report[name] = {'passed': True, 'expected_failure': reason}
print(json.dumps({'passed': True, 'mutations': report}, ensure_ascii=False, indent=2))
