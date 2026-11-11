"""只读检查 SSH 会话和目标容器状态，不收集业务秘密。"""
import json
import subprocess

def run(args):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=15)
    return {'code':result.returncode, 'stdout':result.stdout, 'stderr':result.stderr}

print(json.dumps({'uptime':run(['uptime']), 'memory':run(['free','-m']),
    'trojan':run(['docker','inspect','--format',
        '{{.State.Status}} {{.State.StartedAt}} {{.RestartCount}}','trojan'])},ensure_ascii=False))
