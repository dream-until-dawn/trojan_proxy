"""有界短时只读HTTP诊断，不改变配置或重启容器。"""
import argparse
import datetime
import json
import os
from pathlib import Path
import time
from checks import CheckFailure
from http_checks import web_checks
from domain_checks import domain_checks, validate_domains

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--domain', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--duration-seconds', type=int, default=600)
parser.add_argument('--interval-seconds', type=int, default=3)
parser.add_argument('--manifest', help='可选已核验清单，提供后台端口/路径/独立域及逐域探针')
args = parser.parse_args()
if not 1 <= args.duration_seconds <= 1800 or not 2 <= args.interval_seconds <= 60: parser.error('诊断最多1800秒，每轮间隔至少2秒')
manifest = {}
if args.manifest:
    with open(args.manifest) as source: manifest = json.load(source)
    if manifest.get('passed') is not True: raise CheckFailure('verified_manifest_required')
domains = validate_domains(manifest.get('domain_probes', []), manifest.get('admin_domain'))
output = Path(args.output).resolve();output.mkdir(mode=0o700, parents=True, exist_ok=True)
if output.stat().st_mode & 0o077: raise SystemExit('诊断目录必须0700且位于私有目录')
history = os.fdopen(os.open(str(output/'http.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'w')
summary = {'completed': False, 'samples': 0, 'failures': 0, 'failure_details': []}
deadline = time.monotonic() + args.duration_seconds
try:
    while time.monotonic() < deadline:
        started = time.monotonic()
        sample = {'at_utc': datetime.datetime.utcnow().isoformat()+'Z', 'passed': False, 'http_checks': []}
        try:
            web_checks(args.domain, manifest.get('admin_port', 8007), 18443, 18090, sample['http_checks'],
                       manifest.get('https_routes', []), manifest.get('admin_path', ''), manifest.get('admin_domain'))
            if domains:
                sample['domain_checks'] = []
                sample['domain_certificates'] = domain_checks(domains, sample['domain_checks'])
            sample['passed'] = True
        except CheckFailure as error:
            sample.update(reason=str(error), details=error.details)
            summary['failures'] += 1
            summary['failure_details'] = (summary['failure_details'] + [sample])[-20:]
        summary['samples'] += 1
        history.write(json.dumps(sample)+'\n');history.flush()
        temporary=output/'summary.next'
        with os.fdopen(os.open(str(temporary),os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600),'w') as f:json.dump(summary,f,indent=2)
        os.replace(str(temporary),str(output/'summary.json'))
        time.sleep(max(0,min(deadline-time.monotonic(),args.interval_seconds-(time.monotonic()-started))))
    summary['completed'] = True
finally:
    history.close()
    with os.fdopen(os.open(str(output/'summary.next'),os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600),'w') as f:json.dump(summary,f,indent=2)
    os.replace(str(output/'summary.next'),str(output/'summary.json'))
print(json.dumps(summary,indent=2))
