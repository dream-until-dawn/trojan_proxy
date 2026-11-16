"""正式发行包：只打包已跟踪的公开文件，绑定已验证镜像及明确的项目范围验收。"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_PATHS = ['cmd', 'internal', 'engines', 'go.mod', 'go.sum',
                 'deploy/default.proxy.json', 'deploy/Dockerfile.control',
                 'deploy/Dockerfile.runner', 'deploy/Dockerfile.gateway',
                 'deploy/Dockerfile.control.dockerignore', 'deploy/Dockerfile.runner.dockerignore',
                 'deploy/Dockerfile.gateway.dockerignore']
REQUIRED_CHECKS = {'packaged_binaries_and_local_images', 'three_modules_test_vet',
                   'linux_race', 'control_linux_source_scan', 'trojan_linux_source_scan',
                   'gateway_linux_source_scan', 'default_deployment', 'shared443',
                   'shared443_acme', 'private_listener', 'private_listener_mutation',
                   'subscription_mutation', 'recovery_mutation', 'gateway_cache_mount_mutation'}


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root).decode('utf-8').strip()


def evidence(root, relative):
    """发布指针不能读取仓库外文件，也不能用符号链接偷带本机数据。"""
    path = PurePosixPath(relative)
    if path.is_absolute() or '..' in path.parts or not relative.startswith('docs/evidence/'):
        raise ValueError('evidence_path_outside_repository')
    target = root / path
    if target.is_symlink() or not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('evidence_path_outside_repository')
    return json.loads(target.read_text(encoding='utf-8'))


def validate(root, version):
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version):
        raise ValueError('stable_version_required')
    pointer = json.loads((root / 'deploy/release.json').read_text(encoding='utf-8'))
    if pointer.get('candidate_only') is not False or pointer.get('version') != version:
        raise ValueError('stable_release_pointer_required')
    registry = evidence(root, pointer['registry_proof'])
    gate = evidence(root, pointer['ci_gate'])
    acceptance = evidence(root, pointer['acceptance_proof'])
    audit = evidence(root, pointer['soak_audit'])
    if registry.get('passed') is not True or registry.get('complete_anonymous_pull_verified') is not True:
        raise ValueError('anonymous_images_not_verified')
    checks = gate.get('checks', {})
    if gate.get('passed') is not True or len(checks) < 45 or not REQUIRED_CHECKS.issubset(checks) or set(checks.values()) != {'passed'}:
        raise ValueError('full_ci_gate_required')
    source = registry.get('commit', '')
    if not re.fullmatch('[0-9a-f]{40}', source) or source != gate.get('commit'):
        raise ValueError('image_ci_source_mismatch')
    # 文档/发行工具可以独立收尾，但运行代码改变后不能沿用旧镜像或旧长稳。
    if git(root, 'diff', source, '--', *RUNTIME_PATHS):
        raise ValueError('runtime_source_drift_requires_new_images')
    compose = (root / 'deploy/compose.yaml').read_text(encoding='utf-8')
    if set(registry.get('images', {})) != {'control', 'runner', 'gateway'}:
        raise ValueError('three_images_required')
    for role, item in registry['images'].items():
        tag = 'trojan-control:m6' if role == 'control' else 'trojan-' + role + ':dev'
        reference = item.get('reference', '')
        if not re.fullmatch('ghcr.io/dream-until-dawn/trojan-proxy-' + role + '@sha256:[0-9a-f]{64}', reference) or reference not in compose:
            raise ValueError('compose_image_digest_mismatch')
        if item.get('config_digest') != gate['images'].get(tag):
            raise ValueError('packaged_image_config_mismatch')
    if acceptance.get('project_scope_accepted') is not True or acceptance.get('original_raw_summary_unchanged') is not True:
        raise ValueError('owner_core_acceptance_required')
    if acceptance.get('samples', 0) < 1441 or acceptance.get('observed_seconds', 0) < 86400 or acceptance.get('public443_positive_negative_checks', 0) < 25 or acceptance.get('core_loopback_checks', 0) < 1441:
        raise ValueError('complete_core_soak_required')
    if audit.get('record_consistency_and_checks_valid') is not True or audit.get('observation_complete') is not True or audit.get('raw_samples_reviewed') != acceptance['samples'] or audit.get('raw_deep_checks') != acceptance['public443_positive_negative_checks']:
        raise ValueError('original_soak_audit_required')
    if acceptance.get('original_raw_sha256') != audit.get('raw_prefix_sha256') or audit.get('raw_failures') != len(acceptance.get('external_upstream_exceptions', [])):
        raise ValueError('original_failure_evidence_mismatch')
    return registry, gate, acceptance, audit


def selected_files(root):
    """明确白名单，不扫描工作目录，排除.git、本地产物和旧版启动脚本。"""
    result = []
    for name in git(root, 'ls-files').splitlines():
        if name not in {'README.md', 'LICENSE', 'deploy/compose.yaml', 'deploy/release.json'} and not name.startswith('docs/'):
            continue
        path = root / name
        if path.is_symlink() or path.suffix.lower() in {'.pem', '.key', '.db', '.tgz', '.zip'}:
            raise ValueError('private_or_symlink_file_in_distribution')
        if b'PRIVATE KEY-----' in path.read_bytes():
            raise ValueError('private_key_in_distribution')
        result.append(name)
    required = {'README.md', 'LICENSE', 'deploy/compose.yaml', 'deploy/release.json',
                'docs/user-guide/quickstart.html', 'docs/user-guide/configuration.html'}
    if not required.issubset(result):
        raise ValueError('distribution_entry_missing')
    return sorted(result)


def build(root, version, output):
    if git(root, 'status', '--porcelain'):
        raise ValueError('clean_source_commit_required')
    registry, gate, acceptance, audit = validate(root, version)
    commit = git(root, 'rev-parse', 'HEAD')
    names = selected_files(root)
    manifest = {'format': 1, 'version': version, 'candidate_only': False,
                'deployment_source_commit': commit, 'image_source_commit': registry['commit'],
                'runtime_source_equivalent': True, 'images': registry['images'],
                'ci_checks': len(gate['checks']), 'soak_scope': 'project_core_owner_accepted',
                'soak_samples': acceptance['samples'], 'soak_deep_checks': acceptance['public443_positive_negative_checks'],
                'strict_end_to_end_passed': audit['review_passed'],
                'external_upstream_failures_preserved': audit['raw_failures'],
                'entry': 'docs/user-guide/quickstart.html', 'start_directory': 'deploy',
                'start_command': 'mkdir -p public && docker compose up -d --pull missing',
                'platform': 'linux/amd64'}
    prefix = 'trojan-proxy-' + version + '/'
    output = output.resolve();output.parent.mkdir(parents=True, exist_ok=True)
    stamp = int(git(root, 'show', '-s', '--format=%ct', 'HEAD'))
    date = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).timetuple()[:6]
    def put(archive, name, body):
        info = zipfile.ZipInfo(prefix + name, date_time=date)
        info.create_system = 3
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        archive.writestr(info, body)
    with zipfile.ZipFile(output, 'w') as archive:
        for name in names:
            # 从提交对象取字节，避免Windows检出换行影响Linux发行包摘要。
            body = subprocess.check_output(['git', 'show', 'HEAD:' + name], cwd=root)
            put(archive, name, body)
        put(archive, 'deploy/public/.gitkeep', b'')
        put(archive, 'release-manifest.json', (json.dumps(manifest, ensure_ascii=False, indent=2)+'\n').encode())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + '.sha256').write_text(digest + '  ' + output.name + '\n', encoding='ascii')
    output.with_suffix('.manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    notes = f'''Trojan Proxy {version}\n\nLinux/amd64 单管理员 HTTPS 网关与 Trojan 管理平台。\n\n首次使用：下载 ZIP 与同名 .sha256 校验文件，校验后解压，打开 docs/user-guide/quickstart.html。\n在 deploy 目录执行 mkdir -p public && docker compose up -d --pull missing；首次管理员绑定必须使用 SSH 隧道。\n完整功能、配置字段、反代示例、证书、订阅、维护恢复及排障见包内 HTML 手册。\n\n三个镜像固定摘要，45项候选CI通过；运行源码与已验收镜像源码相同。完整24小时、1441条核心样本、25次真实VPN正反向经所有者按本项目范围验收通过。原整站2次外部期货上游502保留，不宣称整站零失败。\n\n发行源码：{commit}\n镜像源码：{registry['commit']}\nZIP SHA256：{digest}\n\n本次发布不自动升级或重启既有服务器。旧版 acme.sh/nginx 单容器部署与本版命令不兼容；旧用户先备份再按新部署迁移。\n'''
    output.with_suffix('.release-notes.txt').write_text(notes, encoding='utf-8')
    return dict(manifest, archive=output.name, archive_sha256=digest, archive_bytes=output.stat().st_size)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / '.work' / ('trojan-proxy-' + args.version + '.zip')
    print(json.dumps(build(ROOT, args.version, output), ensure_ascii=False, indent=2))


if __name__ == '__main__':main()
