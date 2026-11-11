"""默认页和爬虫声明的定向破坏，网关优先级以真实Caddy响应验证。"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
target = root / '.work/welcome-mutations'
cases = [
    ('escaping', 'welcome/page.go', '"html/template"', '"text/template"',
     'welcome display name was not escaped', False),
    ('robots-priority', 'gateway/public.go',
     'append([]any{header, robots}, server["routes"].([]any)...)',
     'append(server["routes"].([]any), header, robots)',
     'robots did not override root proxy', True),
    ('crawl-header', 'gateway/public.go', '"X-Robots-Tag": []string{robotsTag}', '"X-Probe-Removed": []string{robotsTag}',
     'upstream overrode crawl declaration', True),
]
report = {}
for name, filename, old, new, reason, native in cases:
    directory = target / name
    shutil.copytree(root / 'internal', directory / 'internal', dirs_exist_ok=True)
    for filename_module in ('go.mod', 'go.sum'):
        shutil.copyfile(root / filename_module, directory / filename_module)
    path = directory / 'internal' / filename
    source = path.read_text(encoding='utf-8')
    assert source.count(old) == 1, (name, source.count(old))
    path.write_text(source.replace(old, new), encoding='utf-8')
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    if native:
        binary = directory / 'gateway.test'
        subprocess.run(['go', 'test', '-C', str(directory), '-c', '-tags', 'integration', '-o', str(binary), './internal/gateway'],
                       env=dict(env, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0'), check=True, timeout=90)
        result = subprocess.run([sys.executable, str(root / 'tools/probes/gateway_lifecycle_probe.py')],
                                env=dict(env, TROJAN_GATEWAY_PROBE_BINARY=str(binary)),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=120)
    else:
        for setting in ('GOOS', 'GOARCH', 'CGO_ENABLED'):
            env.pop(setting, None)
        result = subprocess.run(['go', 'test', '-C', str(directory), './internal/welcome', '-count=1'],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
    assert result.returncode != 0 and reason in result.stdout, (name, result.returncode, result.stdout)
    report[name] = {'passed': True, 'expected_failure': reason}
print(json.dumps({'passed': True, 'mutations': report}, ensure_ascii=False, indent=2))
