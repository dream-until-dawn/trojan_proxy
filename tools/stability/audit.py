"""只读重算原始长稳样本；不相信汇总中的单独passed标志。兼容服务器Python3.6。"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re


def timestamp(value):
    for pattern in ('%Y-%m-%dT%H:%M:%S.%fZ', '%Y-%m-%dT%H:%M:%SZ'):
        try: return datetime.datetime.strptime(value, pattern).replace(tzinfo=datetime.timezone.utc).timestamp()
        except (ValueError, TypeError): pass
    raise ValueError('invalid timestamp')


def required_http(manifest):
    admin = manifest.get('admin_port', 8007)
    prefix = manifest.get('admin_path', '')
    expected = {(18090, '/healthz', 'GET'): 200, (80, '/', 'GET'): 308,
                (80, '/robots.txt', 'GET'): 200, (443, '/', 'GET'): 200,
                (admin, prefix + '/api/vpn/status', 'POST'): 401}
    for route in manifest.get('https_routes', []): expected[(route['port'], route['path'], 'GET')] = route['expected']
    return expected


def audit_records(summary, records, manifest, now=None, interval=60):
    findings = []
    expected = required_http(manifest)
    times, deep_times, certificates = [], [], set()
    failures = 0
    for number, sample in enumerate(records, 1):
        at = timestamp(sample.get('at_utc'))
        times.append(at)
        if sample.get('vpn_positive_and_negative') is True: deep_times.append(at)
        if sample.get('passed') is not True:
            failures += 1
            continue
        actual = {}
        for check in sample.get('http_checks', []):
            key = (check.get('port'), check.get('path'), check.get('method'))
            if key in actual: findings.append('duplicate_http_check_at_' + str(number))
            actual[key] = check
        if set(actual) != set(expected): findings.append('http_inventory_mismatch_at_' + str(number))
        for key, status in expected.items():
            check = actual.get(key, {})
            if check.get('expected') != status or check.get('actual') != status or 'exception_type' in check:
                findings.append('http_verdict_mismatch_at_' + str(number))
        certificate = sample.get('certificate_sha256', '')
        if not isinstance(certificate, str) or not re.fullmatch('[0-9a-f]{64}', certificate):
            findings.append('certificate_missing_at_' + str(number))
        else: certificates.add(certificate)
    if len(records) != summary.get('samples'): findings.append('sample_count_mismatch')
    if failures != summary.get('failures'): findings.append('failure_count_mismatch')
    if len(deep_times) != summary.get('deep_checks'): findings.append('deep_count_mismatch')
    gaps = [b-a for a,b in zip(times, times[1:])]
    deep_gaps = [b-a for a,b in zip(deep_times, deep_times[1:])]
    if not times: findings.append('no_samples')
    if any(gap <= 0 for gap in gaps): findings.append('non_increasing_sample_time')
    if gaps and max(gaps) > interval+90: findings.append('sample_gap_exceeded')
    if times and abs(times[0]-timestamp(summary['started_utc'])) > 5: findings.append('first_sample_not_at_start')
    if not deep_times or times and deep_times[0] != times[0]: findings.append('initial_deep_check_missing')
    if deep_gaps and max(deep_gaps) > 3750: findings.append('hourly_deep_gap_exceeded')
    if times and deep_times and times[-1]-deep_times[-1] > 3750: findings.append('latest_deep_check_missing')
    if now is not None and times and not summary.get('completed') and now-times[-1] > interval+90:
        findings.append('live_sample_stale')
    completed = summary.get('completed') is True
    duration = summary['duration_seconds']
    if completed:
        if summary.get('elapsed_seconds', 0) < duration or not times or times[-1]-times[0] < duration-1:
            findings.append('premature_completion')
        if len(records) < int(duration//interval)+1: findings.append('insufficient_sample_count')
        if len(deep_times) < max(2, int(duration//3600)+1): findings.append('insufficient_deep_checks')
        if not deep_times or not times or deep_times[-1] != times[-1]: findings.append('final_deep_check_missing')
    valid = not findings and failures == 0
    raw_passed = completed and valid
    if summary.get('passed') is True and not raw_passed: findings.append('summary_pass_not_supported')
    if raw_passed and summary.get('passed') is not True: findings.append('summary_verdict_mismatch')
    review_passed = raw_passed and summary.get('passed') is True
    return {'record_consistency_and_checks_valid': not findings, 'observation_complete': completed,
            'review_passed': review_passed and not findings, 'raw_samples_reviewed': len(records),
            'raw_failures': failures, 'raw_deep_checks': len(deep_times),
            'observed_span_seconds': round(times[-1]-times[0], 3) if times else 0,
            'max_sample_gap_seconds': round(max(gaps), 3) if gaps else 0,
            'max_deep_gap_seconds': round(max(deep_gaps), 3) if deep_gaps else 0,
            'certificate_fingerprint_count': len(certificates), 'findings': sorted(set(findings))}


def read_snapshot(directory):
    directory = Path(directory)
    with (directory/'summary.json').open() as source: summary = json.load(source)
    count = summary.get('samples')
    if type(count) is not int or not 0 <= count <= 100000: raise ValueError('invalid sample count budget')
    records, digest = [], hashlib.sha256()
    total = 0
    with (directory/'samples.jsonl').open('rb') as source:
        for _ in range(count):
            raw = source.readline(1000001)
            if not raw: break
            if len(raw) > 1000000 or not raw.endswith(b'\n'): raise ValueError('truncated or oversized raw sample')
            total += len(raw)
            if total > 64*1024*1024: raise ValueError('raw snapshot exceeds read budget')
            digest.update(raw);records.append(json.loads(raw))
    return summary, records, digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    summary, records, digest = read_snapshot(args.directory)
    with open(args.manifest) as source: manifest = json.load(source)
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    result = audit_records(summary, records, manifest, now)
    result.update({'summary_completed': summary.get('completed'), 'summary_passed': summary.get('passed'),
                   'raw_prefix_sha256': digest, 'hash_scope': 'first N complete original rows where N is captured summary.samples',
                   'started_utc': summary['started_utc'], 'updated_utc': summary.get('updated_utc'),
                   'runtime_manifest_commit': manifest.get('commit')})
    print(json.dumps(result, indent=2))
    return 0 if result['record_consistency_and_checks_valid'] else 1


if __name__ == '__main__': raise SystemExit(main())
