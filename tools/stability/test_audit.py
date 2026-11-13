import copy
import datetime
import json
from pathlib import Path
import tempfile
import unittest
from audit import audit_records, read_snapshot, required_http


class RawObservationAuditTest(unittest.TestCase):
    def fixture(self, completed=True):
        manifest = {'admin_port':443,'admin_path':'/proxy','https_routes':[{'port':443,'path':'/futures/login','expected':200}]}
        records=[]
        start=datetime.datetime(2026,1,1,tzinfo=datetime.timezone.utc)
        for seconds in [0,60,120]:
            records.append({'at_utc':(start+datetime.timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                            'passed':True,'certificate_sha256':'a'*64,
                            'http_checks':[{'port':p,'path':path,'method':m,'expected':code,'actual':code} for (p,path,m),code in required_http(manifest).items()]})
        records[0]['vpn_positive_and_negative']=True
        records[-1]['vpn_positive_and_negative']=True
        summary={'samples':3,'failures':0,'deep_checks':2,'duration_seconds':120,'elapsed_seconds':123,
                 'completed':completed,'passed':completed,'started_utc':records[0]['at_utc']}
        return summary,records,manifest

    def test_complete_positive_and_unfinished_zero_failures(self):
        summary,records,manifest=self.fixture()
        self.assertTrue(audit_records(summary,records,manifest)['review_passed'])
        summary['completed']=False;summary['passed']=False
        result=audit_records(summary,records,manifest)
        self.assertTrue(result['record_consistency_and_checks_valid']);self.assertFalse(result['review_passed'])

    def test_summary_cannot_hide_failures_or_bad_http(self):
        summary,records,manifest=self.fixture()
        records[1]['passed']=False
        self.assertIn('failure_count_mismatch',audit_records(summary,records,manifest)['findings'])
        summary,records,manifest=self.fixture();records[1]['http_checks'][0]['actual']=503
        self.assertIn('http_verdict_mismatch_at_2',audit_records(summary,records,manifest)['findings'])
        summary,records,manifest=self.fixture();records[1]['http_checks'].append(copy.deepcopy(records[1]['http_checks'][0]))
        self.assertIn('duplicate_http_check_at_2',audit_records(summary,records,manifest)['findings'])

    def test_missing_rows_gap_and_deep_check_rejected(self):
        summary,records,manifest=self.fixture()
        self.assertIn('sample_count_mismatch',audit_records(summary,records[:-1],manifest)['findings'])
        records[1]['at_utc']='2026-01-01T00:05:00Z';records[2]['at_utc']='2026-01-01T00:06:00Z'
        self.assertIn('sample_gap_exceeded',audit_records(summary,records,manifest)['findings'])
        summary,records,manifest=self.fixture();records[-1].pop('vpn_positive_and_negative')
        self.assertIn('final_deep_check_missing',audit_records(summary,records,manifest)['findings'])
        summary,records,manifest=self.fixture();summary['elapsed_seconds']=119
        self.assertIn('premature_completion',audit_records(summary,records,manifest)['findings'])

    def test_auditor_cannot_promote_failed_summary_and_stale_stream(self):
        summary,records,manifest=self.fixture();summary['passed']=False
        result=audit_records(summary,records,manifest)
        self.assertFalse(result['review_passed']);self.assertIn('summary_verdict_mismatch',result['findings'])
        summary['completed']=False
        self.assertIn('live_sample_stale',audit_records(summary,records,manifest,now=1767226000)['findings'])

    def test_snapshot_prefix_is_bounded_and_truncation_rejected(self):
        summary,records,manifest=self.fixture()
        with tempfile.TemporaryDirectory() as value:
            path=Path(value);(path/'summary.json').write_text(json.dumps(summary),encoding='utf-8')
            text=''.join(json.dumps(x)+'\n' for x in records)
            (path/'samples.jsonl').write_bytes((text+'not-part-of-captured-prefix').encode())
            _,actual,digest=read_snapshot(path);self.assertEqual(actual,records);self.assertEqual(len(digest),64)
            (path/'samples.jsonl').write_bytes(text[:-1].encode())
            with self.assertRaisesRegex(ValueError,'truncated'):read_snapshot(path)

    def test_oversized_record_is_rejected_before_json_parse(self):
        with tempfile.TemporaryDirectory() as value:
            path=Path(value);(path/'summary.json').write_text('{"samples":1}',encoding='utf-8')
            (path/'samples.jsonl').write_bytes(b'x'*1000001+b'\n')
            with self.assertRaisesRegex(ValueError,'oversized'):read_snapshot(path)


if __name__=='__main__':unittest.main()
