"""证书就绪、导入配额、路径边界及近期MFA的定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root = Path(__file__).resolve().parents[2]
target = root / '.work/certificate-control-mutations' / uuid.uuid4().hex[:10]
cases = [
    ('automatic-readiness', 'site/planner.go', 'AwaitCertificate: err != nil', 'AwaitCertificate: false',
     'site', 'TestPlannerCertificateReadinessAndExpiryDriveIngress', 'missing automatic certificate falsely ready'),
    ('imported-no-silent-issuer-change', 'site/planner.go', '&gateway.Ingress{Mode: "unavailable"}', '&gateway.Ingress{Mode: "automatic"}',
     'site', 'TestPlannerCertificateReadinessAndExpiryDriveIngress', 'expired imported certificate silently changed issuer'),
    ('import-budget', 'certificates/manager.go', 'if len(entries) >= 64 {', 'if false && len(entries) >= 64 {',
     'certificates', 'TestManagerImportSelectionExpiryAndBudget', 'certificate import exceeded bounded storage'),
    ('version-path', 'certificates/manager.go', 'if !managedVersion.MatchString(selection.ImportedVersion) {', 'if false && !managedVersion.MatchString(selection.ImportedVersion) {',
     'certificates', 'TestManagerImportSelectionExpiryAndBudget', 'unsafe certificate selection accepted'),
    ('import-recent-mfa', 'api/certificates.go', 'if !s.Auth.Recent(bearer(r)) {', 'if false && !s.Auth.Recent(bearer(r)) {',
     'api', 'TestCertificateImportAuthenticationBudgetAndNoSecretEcho', 'certificate import bypassed recent MFA'),
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
