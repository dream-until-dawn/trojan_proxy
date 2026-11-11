"""构建绑定当前干净提交的三个候选镜像和离线包，不自动部署或发布。"""
import gzip
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]


def run(arguments):
    return subprocess.check_output(arguments, cwd=root, text=True).strip()


if run(['git', 'status', '--porcelain']):
    raise SystemExit('请先提交源码，候选镜像必须绑定干净提交')
commit = run(['git', 'rev-parse', 'HEAD'])
images = [('control', 'trojan-control:m6'), ('runner', 'trojan-runner:dev'), ('gateway', 'trojan-gateway:dev')]
for role, tag in images:
    subprocess.run(['docker', 'build', '-f', 'deploy/Dockerfile.' + role, '-t', tag,
                    '--label', 'org.opencontainers.image.revision=' + commit,
                    '--label', 'org.opencontainers.image.source=https://github.com/dream-until-dawn/trojan_proxy', '.'],
                   cwd=root, check=True)
directory = root / '.work'
directory.mkdir(exist_ok=True)
plain = directory / 'candidate-images.tar'
archive = directory / 'candidate-images.tar.gz'
subprocess.run(['docker', 'image', 'save', '-o', str(plain), *[tag for _, tag in images]], cwd=root, check=True)
try:
    with plain.open('rb') as source, gzip.open(archive, 'wb') as destination:
        shutil.copyfileobj(source, destination)
finally:
    plain.unlink(missing_ok=True)
print('候选提交:', commit, '离线包:', archive)
