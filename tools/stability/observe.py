"""一次有截止时间的服务器只读长稳测试；不会重启服务或发送消息。"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from checks import CheckFailure, SERVICE_ROLES, completed_pass, validate_containers, validate_vpn
from http_checks import web_checks


def command(arguments, timeout=20):
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
    if result.returncode: raise CheckFailure('diagnostic_command_failed')
    return result.stdout


def utc():
    return datetime.datetime.utcnow().isoformat() + 'Z'


def inspect(project):
    ids = command(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]).split()
    if not ids: raise CheckFailure('project_not_running')
    return json.loads(command(['docker', 'inspect'] + ids))


def private_output(output, containers):
    output = Path(output).resolve()
    for container in containers:
        if container['Config'].get('Labels', {}).get('com.docker.compose.service') != 'control': continue
        for mount in container.get('Mounts', []):
            if mount['Destination'].startswith('/srv/public'):
                root = os.path.realpath(mount['Source'])
                if os.path.commonpath([root, str(output)]) == root: raise CheckFailure('output_must_not_be_public')
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output.stat().st_mode & 0o077: raise CheckFailure('output_directory_must_be_private')
    return output


def runtime_resources(containers):
    """核对内核实际降权；资源值来自本项目完整容器，不把runner父进程RSS当作总内存。"""
    owned = [c for c in containers if c['Config'].get('Labels', {}).get('com.docker.compose.service') in SERVICE_ROLES]
    for container in owned:
        service = container['Config']['Labels']['com.docker.compose.service']
        with open('/proc/' + str(container['State']['Pid']) + '/status') as source:
            fields = dict(line.split(':', 1) for line in source if ':' in line)
        uid = 10002 if service == 'vpn-runner' else 10001
        capability = 0x400 if service == 'admin-gateway' else 0
        if [int(value) for value in fields['Uid'].split()] != [uid] * 4 or fields['NoNewPrivs'].strip() != '1': raise CheckFailure('runtime_identity_or_no_new_privs_changed')
        if any(int(fields[key], 16) != capability for key in ['CapEff', 'CapPrm', 'CapInh', 'CapBnd', 'CapAmb']): raise CheckFailure('runtime_capabilities_changed')
    stats = command(['docker', 'stats', '--no-stream', '--format', '{{json .}}'] + [c['Id'] for c in owned])
    return [{key: row.get(key) for key in ['Name', 'CPUPerc', 'MemUsage', 'MemPerc', 'PIDs']}
            for row in [json.loads(line) for line in stats.splitlines() if line]]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--admin-port', type=int, default=8007)
    parser.add_argument('--vpn-port', type=int, default=18443)
    parser.add_argument('--control-port', type=int, default=18090)
    parser.add_argument('--duration-seconds', type=int, default=86400)
    parser.add_argument('--interval-seconds', type=int, default=60)
    parser.add_argument('--vpn-diagnostic', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    if not 1 <= args.duration_seconds <= 86400 or not 1 <= args.interval_seconds <= 300: parser.error('只允许1至86400秒的有界观察及1至300秒间隔')
    with open(args.manifest) as source: manifest = json.load(source)
    if manifest.get('passed') is not True: raise CheckFailure('verified_manifest_required')
    initial = inspect(args.project)
    output = private_output(args.output, initial)
    lock = os.fdopen(os.open(str(output / 'observer.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if (output / 'summary.json').exists(): raise CheckFailure('observation_output_already_used')
    history = os.fdopen(os.open(str(output / 'samples.jsonl'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')
    summary = {'passed': False, 'completed': False, 'started_utc': utc(), 'duration_seconds': args.duration_seconds,
               'source_commit': manifest['commit'], 'samples': 0, 'failures': 0, 'deep_checks': 0, 'recent_failures': []}
    started = time.monotonic();deadline = started + args.duration_seconds;next_deep = started
    next_sample = started;previous_sample = None;baseline = None;stopped = [False]
    def stop(signum, frame): stopped[0] = True
    signal.signal(signal.SIGTERM, stop);signal.signal(signal.SIGINT, stop)
    def save():
        # 先落临时文件再替换，读者不会把写到一半的摘要误判为成功。
        summary['updated_utc'] = utc();summary['elapsed_seconds'] = time.monotonic() - started
        path = output / 'summary.next'
        with os.fdopen(os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600), 'w') as destination:
            json.dump(summary, destination, indent=2);destination.flush();os.fsync(destination.fileno())
        os.replace(str(path), str(output / 'summary.json'))
    try:
        while not stopped[0]:
            now = time.monotonic();final = now >= deadline
            sample = {'at_utc': utc(), 'passed': False}
            try:
                containers = inspect(args.project)
                current = validate_containers(containers, manifest['images'], baseline)
                if baseline is None: baseline = current
                sample['resources'] = runtime_resources(containers)
                if previous_sample is not None and now - previous_sample > args.interval_seconds + 90: raise CheckFailure('sampling_gap')
                sample['http_checks'] = []
                sample['certificate_sha256'] = web_checks(args.domain, args.admin_port, args.vpn_port, args.control_port, sample['http_checks'])['443']
                if now >= next_deep or final:
                    raw = command([sys.executable, args.vpn_diagnostic, '--project', args.project, '--domain', args.domain], timeout=85)
                    validate_vpn(json.loads(raw));summary['deep_checks'] += 1;sample['vpn_positive_and_negative'] = True
                    while next_deep <= now: next_deep += 3600
                sample['passed'] = True
            except Exception as error:
                # 保留累计失败；后续恢复不抹掉本轮已经发生的故障。
                sample['reason'] = str(error) if isinstance(error, CheckFailure) else type(error).__name__
                if isinstance(error, CheckFailure): sample['details'] = error.details
                summary['failures'] += 1;summary['recent_failures'] = (summary['recent_failures'] + [sample])[-50:]
            summary['samples'] += 1;previous_sample = now
            history.write(json.dumps(sample) + '\n');history.flush()
            summary['completed'] = final
            summary['passed'] = completed_pass(args.duration_seconds, time.monotonic() - started, summary['failures'], summary['deep_checks'], final)
            save()
            if final: break
            next_sample += args.interval_seconds
            remaining = min(next_sample, deadline) - time.monotonic()
            while remaining > 0 and not stopped[0]:
                time.sleep(min(remaining, 1));remaining = min(next_sample, deadline) - time.monotonic()
        if stopped[0]: summary['completed'] = False;summary['passed'] = False;save()
    finally:
        history.close();lock.close()
    print(json.dumps(summary, indent=2))
    return 0 if summary['passed'] else 1


if __name__ == '__main__': raise SystemExit(main())
