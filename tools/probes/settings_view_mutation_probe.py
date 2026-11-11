"""持久设置读取、临时入口保护、候选目录与来源期限的定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
target = root / '.work/settings-view-mutations' / uuid.uuid4().hex[:10]
cases = [
    ('reconcile-pending', 'routing/service.go', 'if !s.frozen && j.Applied.GatewaySettings != digest {', 'if j.Applied.GatewaySettings != digest {',
     'routing', 'TestPersistentSettingsAndPendingEntrySurviveReconcile', 'reconcile destroyed pending dual entry'),
    ('core-write-freeze', 'routing/service.go', 'if s.frozen {', 'if false && s.frozen {',
     'routing', 'TestPersistentSettingsAndPendingEntrySurviveReconcile', 'route service bypassed pending entry write freeze'),
    ('origin-deadline', 'settings/view.go', 'v.now().Unix() < d.Pending.Deadline', 'v.now().Unix() <= d.Pending.Deadline',
     'settings', 'TestViewProjectsCommittedSettingsAndBoundedOrigins', 'expired candidate origin remained trusted'),
    ('candidate-directory', 'settings/view.go', 'for _, binding := range d.Site.Directories {', 'for _, binding := range append(d.Site.Directories, d.Pending.Candidate.Directories...) {',
     'settings', 'TestViewDirectoryUsesCommittedBindingAndSubroot', 'candidate directory published before confirmation'),
]
report = {}
for name, filename, old, new, package, test, reason in cases:
    directory = target / name
    shutil.copytree(root / 'internal', directory / 'internal')
    for module in ('go.mod', 'go.sum'):
        shutil.copyfile(root / module, directory / module)
    path = directory / 'internal' / filename
    source = path.read_text(encoding='utf-8')
    assert source.count(old) == 1, (name, source.count(old))
    path.write_text(source.replace(old, new), encoding='utf-8')
    result = subprocess.run(['go', 'test', '-C', str(directory), './internal/'+package, '-run', '^'+test+'$', '-count=1'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
    assert result.returncode != 0 and reason in result.stdout, (name, result.returncode, result.stdout)
    report[name] = {'passed': True, 'expected_failure': reason}
print(json.dumps({'passed': True, 'mutations': report}, ensure_ascii=False, indent=2))
