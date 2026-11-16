"""发行门槛正反向：指定原因断言，防止错误证据或旧镜像被包装成正式版本。"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zipfile

import distribution as release


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='trojan-release-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for relative in ['deploy/compose.yaml', 'deploy/release.json', 'README.md', 'LICENSE',
                         'docs/user-guide/quickstart.html', 'docs/user-guide/configuration.html']:
            p = self.root / relative;p.parent.mkdir(parents=True, exist_ok=True)
            source = release.ROOT / relative
            p.write_bytes(source.read_bytes())
        pointer = self.read('deploy/release.json')
        for key in ['registry_proof', 'ci_gate', 'acceptance_proof', 'soak_audit']:
            source = release.ROOT / pointer[key];target = self.root / pointer[key]
            target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(source.read_bytes())
        self.run_git('init', '-q')
        self.run_git('config', 'user.name', 'Release test')
        self.run_git('config', 'user.email', 'release-test@example.invalid')
        self.run_git('config', 'core.autocrlf', 'false')
        (self.root/'.gitignore').write_text('.work/\n',encoding='utf-8')
        runtime=self.root/'internal/sentinel.go';runtime.parent.mkdir();runtime.write_text('package sentinel\n')
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'fixture')
        self.source = self.run_git('rev-parse', 'HEAD')
        # 测试夹具源码必须是真实本地Git提交，不能依赖生产提交的历史存在。
        for key in ['registry_proof', 'ci_gate']:
            d=self.read(pointer[key]);d['commit']=self.source;self.write(pointer[key],d)
        self.run_git('add', '.')
        self.run_git('commit', '-qm', 'bind fixture images to runtime source')

    def run_git(self,*args):
        return subprocess.check_output(['git',*args],cwd=self.root,stderr=subprocess.STDOUT).decode().strip()

    def read(self,p):return json.loads((self.root/p).read_text(encoding='utf-8'))
    def write(self,p,d):(self.root/p).write_text(json.dumps(d,indent=2)+'\n',encoding='utf-8')

    def mutate_evidence(self,key,change):
        pointer=self.read('deploy/release.json');p=pointer[key];d=self.read(p);change(d);self.write(p,d)

    def test_valid_archive_is_reproducible_and_excludes_private_untracked_files(self):
        private=self.root/'.work';private.mkdir();(private/'secret.pem').write_text('PRIVATE FIXTURE ONLY')
        first=release.build(self.root,'v1.0.0',private/'first.zip')
        second=release.build(self.root,'v1.0.0',private/'second.zip')
        self.assertEqual(first['archive_sha256'],second['archive_sha256'])
        with zipfile.ZipFile(private/'first.zip') as archive:
            names=archive.namelist()
            self.assertIn('trojan-proxy-v1.0.0/deploy/compose.yaml',names)
            self.assertIn('trojan-proxy-v1.0.0/deploy/public/.gitkeep',names)
            self.assertFalse(any('.work' in p or p.endswith('.pem') for p in names))
            manifest=json.loads(archive.read('trojan-proxy-v1.0.0/release-manifest.json'))
            self.assertFalse(manifest['strict_end_to_end_passed'])
            self.assertEqual(manifest['external_upstream_failures_preserved'],2)

    def test_missing_owner_acceptance_rejected(self):
        self.mutate_evidence('acceptance_proof',lambda d:d.update(project_scope_accepted=False))
        with self.assertRaisesRegex(ValueError,'owner_core_acceptance_required'):release.validate(self.root,'v1.0.0')

    def test_incomplete_soak_rejected(self):
        self.mutate_evidence('acceptance_proof',lambda d:d.update(observed_seconds=86399))
        with self.assertRaisesRegex(ValueError,'complete_core_soak_required'):release.validate(self.root,'v1.0.0')

    def test_failed_ci_check_rejected(self):
        self.mutate_evidence('ci_gate',lambda d:d['checks'].update(private_listener='failed'))
        with self.assertRaisesRegex(ValueError,'full_ci_gate_required'):release.validate(self.root,'v1.0.0')

    def test_wrong_image_configuration_rejected(self):
        self.mutate_evidence('registry_proof',lambda d:d['images']['runner'].update(config_digest='sha256:'+'0'*64))
        with self.assertRaisesRegex(ValueError,'packaged_image_config_mismatch'):release.validate(self.root,'v1.0.0')

    def test_wrong_compose_digest_rejected(self):
        p=self.root/'deploy/compose.yaml';s=p.read_text(encoding='utf-8');ref=self.read(self.read('deploy/release.json')['registry_proof'])['images']['control']['reference'];p.write_text(s.replace(ref,'ghcr.io/other/unverified:latest'),encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'compose_image_digest_mismatch'):release.validate(self.root,'v1.0.0')

    def test_runtime_drift_rejected(self):
        (self.root/'internal/sentinel.go').write_text('package changed\n')
        with self.assertRaisesRegex(ValueError,'runtime_source_drift_requires_new_images'):release.validate(self.root,'v1.0.0')

    def test_original_failures_cannot_be_erased(self):
        self.mutate_evidence('soak_audit',lambda d:d.update(raw_failures=0))
        with self.assertRaisesRegex(ValueError,'original_failure_evidence_mismatch'):release.validate(self.root,'v1.0.0')

    def test_repository_escape_rejected(self):
        with self.assertRaisesRegex(ValueError,'evidence_path_outside_repository'):release.evidence(self.root,'../secret.json')
        with self.assertRaisesRegex(ValueError,'evidence_path_outside_repository'):release.evidence(self.root,'/etc/passwd')

    def test_dirty_archive_and_prerelease_version_rejected(self):
        (self.root/'README.md').write_text('uncommitted')
        with self.assertRaisesRegex(ValueError,'clean_source_commit_required'):release.build(self.root,'v1.0.0',self.root/'.work/out.zip')
        with self.assertRaisesRegex(ValueError,'stable_version_required'):release.validate(self.root,'v1.0.0-rc1')

    def test_private_key_in_tracked_docs_rejected(self):
        p=self.root/'docs/leak.html';p.write_text('-----BEGIN PRIVATE KEY-----\nfixture only')
        self.run_git('add','docs/leak.html')
        with self.assertRaisesRegex(ValueError,'private_key_in_distribution'):release.selected_files(self.root)


if __name__=='__main__':unittest.main()
