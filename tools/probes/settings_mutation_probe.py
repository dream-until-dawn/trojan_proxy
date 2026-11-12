"""业务设置持久化与部署边界的定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]
target = root / '.work/settings-mutations'
cases = [
    ('path-reader-protection', 'storage/format.go', 'version = 5',
     'version = 4', './internal/storage', 'TestAdminPathFormatProtectsCandidatesAndCompatibleRollback',
     'path candidate did not reject legacy readers'),
    ('path-confirmation-identity', 'settings/transition.go', 'origin != m.candidateEntry(d.Pending.Candidate)',
     'false', './internal/settings', 'TestPathConfirmationUsesFullEndpointIdentity',
     'wrong management identity confirmed candidate'),
    ('import-once', 'settings/migration.go', 'if journal.Applied.Settings != "" {',
     'if false && journal.Applied.Settings != "" {', './internal/settings', 'TestPersistedSettingsSurviveStaticChanges',
     'static JSON overwrote persisted business settings'),
    ('trusted-root', 'settings/model.go', 'deployment.PublicDirectories[directory.Root] == ""',
     'false', './internal/settings', 'TestStrictSettingsAndTrustedMountBoundary/untrusted-root',
     'unsafe settings accepted untrusted-root'),
    ('revision-protection', 'storage/journal.go', ' && j.Applied.Settings == previous.Applied.Settings',
     '', './internal/storage', 'TestGatewayBootstrapDoesNotOverwriteBusinessSettings',
     'gateway bootstrap bypassed settings revision protection'),
    ('old-reader-protection', 'storage/format.go', 'version = 3',
     'version = 2', './internal/storage', 'TestSettingsRequireSchemaThreeWithoutDowngradeOnReopen',
     'new settings did not reject old schema readers'),
    ('new-origin-confirmation', 'settings/transition.go', 'origin != m.candidateEntry(d.Pending.Candidate)',
     'false', './internal/settings', 'TestTransitionRequiresNewOriginAndReadyCertificate',
     'old entry confirmed the new endpoint'),
    ('ready-certificate', 'settings/transition.go', 'if err = m.planner.Ready(ctx, d.Pending.Candidate); err != nil {',
     'if err = m.planner.Ready(ctx, d.Pending.Candidate); false {', './internal/settings', 'TestTransitionRequiresNewOriginAndReadyCertificate',
     'unready certificate accepted'),
    ('deadline-recovery', 'settings/transition.go', 'if d.Pending != nil && m.now().Unix() >= d.Pending.Deadline {',
     'if d.Pending != nil && m.now().Unix() > d.Pending.Deadline {', './internal/settings', 'TestTransitionDeadlineSurvivesManagerRestart',
     'entry deadline did not restore old endpoint'),
    ('write-freeze', 'settings/transition.go', 'if d.Pending != nil {\n\t\treturn ErrFrozen\n\t}\n\treturn nil',
     'if false && d.Pending != nil {\n\t\treturn ErrFrozen\n\t}\n\treturn nil', './internal/settings', 'TestTransitionRequiresNewOriginAndReadyCertificate',
     'ordinary writes allowed while entry waits for confirmation'),
]
report = {}
for name, filename, old, new, package, test, reason in cases:
    directory = target / name
    shutil.copytree(root / 'internal', directory / 'internal', dirs_exist_ok=True)
    for module in ('go.mod', 'go.sum'):
        shutil.copyfile(root / module, directory / module)
    path = directory / 'internal' / filename
    source = path.read_text(encoding='utf-8')
    assert source.count(old) == 1, (name, source.count(old))
    path.write_text(source.replace(old, new), encoding='utf-8')
    result = subprocess.run(['go', 'test', '-C', str(directory), package, '-run', '^'+test+'$', '-count=1'],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', timeout=90)
    assert result.returncode != 0 and reason in result.stdout, (name, result.returncode, result.stdout)
    report[name] = {'passed': True, 'expected_failure': reason}
print(json.dumps({'passed': True, 'mutations': report}, ensure_ascii=False, indent=2))
