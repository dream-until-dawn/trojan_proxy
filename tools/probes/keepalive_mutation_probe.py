"""定向移除内置服务的连接隔离，必须由对应编译契约测试准确拒绝。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
directory = root / '.work/keepalive-mutations' / uuid.uuid4().hex[:10]
shutil.copytree(root / 'internal', directory / 'internal')
for name in ('go.mod', 'go.sum'):
    shutil.copyfile(root / name, directory / name)
path = directory / 'internal/gateway/compile.go'
source = path.read_text(encoding='utf-8')
old = '"keep_alive": map[string]any{"enabled": false}'
assert source.count(old) == 1, 'mutation target changed'
path.write_text(source.replace(old, '"keep_alive": map[string]any{"enabled": true}'), encoding='utf-8')
result = subprocess.run(['go', 'test', '-C', str(directory), './internal/gateway', '-run', '^TestInternalTransportDoesNotChangeUserUpstream$', '-count=1'],
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
reason = 'internal connection reuse was not disabled'
assert result.returncode != 0 and reason in result.stdout, (result.returncode, result.stdout)
print(json.dumps({'passed': True, 'expected_failure': reason}))
