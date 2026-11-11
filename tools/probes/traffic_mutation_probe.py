"""流量记录的去重、30天边界、物理清理及速度分母定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess

root = Path(__file__).resolve().parents[2]
target = root / '.work/traffic-mutations'
cases = [
    ('deduplication', 'traffic/store.go', 'if batch.Sequence <= previous {', 'if false && batch.Sequence <= previous {',
     './internal/traffic', 'TestBatchReplayDirectionAndRetentionBoundary', 'traffic replay/direction/retention incorrect'),
    ('query-retention', 'traffic/store.go', 'from.Before(cutoff)', 'false && from.Before(cutoff)',
     './internal/traffic', 'TestBatchReplayDirectionAndRetentionBoundary', 'query exposed traffic older than 30 days'),
    ('target-retention', 'traffic/query.go', 'from.Before(cutoff)', 'false && from.Before(cutoff)',
     './internal/traffic', 'TestTargetsTimelineSamplingDurationAndQueryRetention', 'target query exposed IP beyond retention'),
    ('physical-purge', 'traffic/store.go', 'WHERE bucket<? LIMIT 5000', 'WHERE bucket<? AND 0 LIMIT 5000',
     './internal/traffic', 'TestBatchReplayDirectionAndRetentionBoundary', 'purge retained expired traffic rows'),
    ('clear-buffer-boundary', 'traffic/store.go', ' || row.Bucket <= discarded', '',
     './internal/traffic', 'TestClearDoesNotResurrectBufferedHistory', 'cleared history resurrected from buffered batch'),
    ('rate-duration', 'traffic/collector.go', 'float64(up) * 1000 / float64(observed)', 'float64(up)',
     './internal/traffic', 'TestCollectorRatesRestartGapAndFailureIsolation', 'live rate ignored actual sample duration'),
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
