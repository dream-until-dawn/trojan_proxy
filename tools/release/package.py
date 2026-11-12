"""打包干净提交的候选源码和固定镜像清单；不会创建正式版本或标签。"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

root = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=root / '.work/trojan-proxy-candidate.zip')
args = parser.parse_args()


def git(arguments):
    return subprocess.check_output(['git'] + arguments, cwd=root, text=True).strip()


if git(['status', '--porcelain']): raise SystemExit('必须先提交源码，再生成绑定干净提交的候选包')
commit = git(['rev-parse', 'HEAD'])
pointer = root / 'deploy/release.json'
proofs = json.loads(pointer.read_text(encoding='utf-8')) if pointer.exists() else {
    'registry_proof': 'docs/evidence/2026-11-11-public-images.json',
    'ci_gate': 'docs/evidence/2026-11-11-candidate-ci-gate.json',
}
# 只读取仓库内的公开证据，拒绝把本机其他文件作为打包清单输入。
for key in ['registry_proof', 'ci_gate']:
    path = Path(proofs[key])
    if path.is_absolute() or '..' in path.parts or not path.as_posix().startswith('docs/evidence/'):
        raise SystemExit('发布证据路径必须位于docs/evidence内')
registry = json.loads((root / proofs['registry_proof']).read_text(encoding='utf-8'))
gate = json.loads((root / proofs['ci_gate']).read_text(encoding='utf-8'))
if not registry['passed'] or not registry['complete_anonymous_pull_verified'] or not gate['passed'] or registry['commit'] != gate['commit']:
    raise SystemExit('公开镜像与实际CI门槛不匹配')
compose = (root / 'deploy/compose.yaml').read_text(encoding='utf-8')
for role, image in registry['images'].items():
    if image['reference'] not in compose: raise SystemExit('默认Compose未固定到已验证镜像摘要')
output = args.output.resolve();output.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(['git', 'archive', '--format=zip', '--prefix=trojan-proxy-candidate/', '--output=' + str(output), commit], cwd=root, check=True)
manifest = {'candidate_only': True, 'deployment_source_commit': commit, 'image_source_commit': registry['commit'],
            'images': registry['images'], 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'entry': 'trojan-proxy-candidate/docs/operations.html', 'start_directory': 'trojan-proxy-candidate/deploy',
            'start_command': 'mkdir -p public && docker compose up -d --pull missing',
            'remaining_gate': 'complete 24 hours of real stability observation before a stable release'}
with zipfile.ZipFile(output, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
    archive.writestr('trojan-proxy-candidate/candidate-manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
digest = hashlib.sha256(output.read_bytes()).hexdigest()
report = dict(manifest, archive=output.name, archive_sha256=digest, archive_bytes=output.stat().st_size)
output.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(report, ensure_ascii=False, indent=2))
