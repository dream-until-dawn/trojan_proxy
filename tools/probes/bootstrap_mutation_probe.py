"""首次绑定定向破坏：每项必须命中特定断言，不接受其他失败代替。"""
import json
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]
target = root / '.work/bootstrap-mutations'
cases = [
    ('token-consumption', 'bootstrap/service.go',
     'next := storage.SetupState{SessionHash:',
     'next := storage.SetupState{TokenHash: state.TokenHash, SessionHash:',
     './internal/bootstrap', 'TestEnrollmentPersistentSingleUseAndLogin',
     'consumed token replay accepted after restart', 1),
    ('expiry-boundary', 'storage/bootstrap.go', 'now.Unix()', '(now.Unix()-1)',
     './internal/bootstrap', 'TestExpiryAndPersistentFailureLimit',
     'expired setup token accepted at exact boundary', 3),
    ('origin', 'bootstrap/http.go',
     'if strings.HasPrefix(r.URL.Path, "/api/") &&', 'if false && strings.HasPrefix(r.URL.Path, "/api/") &&',
     './internal/bootstrap', 'TestLocalHTTPBoundaryAndCompleteFlow',
     'unsafe request accepted', 1),
    ('protected-port', 'routes/rule.go', 'policy.ControlPort + 2: true,', '',
     './internal/routes', 'TestBootstrapPortCannotBePublished',
     'bootstrap upstream became publicly publishable', 1),
]
results = {}
for name, filename, old, new, package, test, reason, expected_count in cases:
    directory = target / name
    shutil.copytree(root / 'internal', directory / 'internal', dirs_exist_ok=True)
    for module in ('go.mod', 'go.sum'):
        shutil.copyfile(root / module, directory / module)
    path = directory / 'internal' / filename
    source = path.read_text(encoding='utf-8')
    assert source.count(old) == expected_count, (name, source.count(old))
    path.write_text(source.replace(old, new), encoding='utf-8')
    result = subprocess.run(['go', 'test', '-C', str(directory), package, '-run', '^'+test+'$', '-count=1'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
    assert result.returncode != 0 and reason in result.stdout, (name, result.returncode, result.stdout)
    results[name] = {'expected_failure': reason, 'passed': True}
print(json.dumps({'passed': True, 'mutations': results}, ensure_ascii=False, indent=2))
