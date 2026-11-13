import copy
import http.client
import http.server
import json
import socketserver
import socket
import threading
import unittest
from unittest.mock import patch
from audit import audit_records
from checks import CheckFailure
from domain_checks import domain_checks, required_domain_http, validate_domains
from http_checks import web_checks
import test_audit


class DomainObservationTest(unittest.TestCase):
    def specs(self):
        return [{'domain': name, 'routes': [{'port': 443, 'path': '/login', 'expected': 200},
                                            {'port': 443, 'path': '/api/private', 'expected': 401}]}
                for name in ('one.fixture.test', 'two.fixture.test')]

    def test_explicit_domains_and_private_paths_only(self):
        specs = self.specs()
        self.assertEqual(validate_domains(specs, 'one.fixture.test'), specs)
        for bad in [dict(specs[0], domain='*.fixture.test'), dict(specs[0], domain='a:443'),
                    dict(specs[0], domain='-bad.fixture.test'), dict(specs[0], domain='a\n.fixture.test'),
                    dict(specs[0], routes=[]), dict(specs[0], routes=[{'port':443,'path':'/?token=secret','expected':200}])]:
            with self.assertRaises(CheckFailure): validate_domains([bad])
        with self.assertRaisesRegex(CheckFailure, 'duplicate_domain_probe'): validate_domains([specs[0]]*2)
        with self.assertRaisesRegex(CheckFailure, 'admin_domain_probe_missing'): validate_domains(specs, 'missing.fixture.test')
        self.assertIn(('two.fixture.test',443,'/api/private','GET'), required_domain_http(specs))

    def test_real_http_host_redirect_noindex_and_distinct_tls_names(self):
        seen = []; wrong_redirect = [False]; tls_names = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                host = self.headers['Host']; seen.append((host, self.path))
                # 测试传输中使用专用标记区分逻辑HTTP/HTTPS，不进入生产请求。
                secure = self.headers.get('X-Fixture-TLS') == 'yes'
                status = 200 if self.path == '/robots.txt' or secure else 308
                if self.path == '/healthz': status = 200
                if self.path == '/api/private': status = 401
                self.send_response(status); self.send_header('X-Robots-Tag','noindex, nofollow')
                if status == 308: self.send_header('Location','https://' + ('wrong.fixture.test' if wrong_redirect[0] else host) + '/')
                self.send_header('Set-Cookie','secret-cookie-sentinel');self.end_headers()
                self.wfile.write(b'User-agent: *\nDisallow: /\n' if self.path == '/robots.txt' else (host.encode() if self.path == '/' else b'secret-body-sentinel'))
            def do_POST(self):
                seen.append((self.headers['Host'],self.path,self.headers.get('Origin')))
                self.send_response(401 if self.headers['Host']=='proxy.fixture.test' and self.headers.get('Origin')=='https://proxy.fixture.test' else 421)
                self.end_headers()
            def log_message(self,*args): pass
        class Server(socketserver.ThreadingMixIn,http.server.HTTPServer): daemon_threads=True
        server=Server(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        original=http.client.HTTPConnection;actual_connect=socket.create_connection
        class FixtureHTTP(original):
            def __init__(self,domain,port,timeout):super().__init__('127.0.0.1',server.server_port,timeout=timeout)
            def connect(self):self.sock=actual_connect(('127.0.0.1',server.server_port),self.timeout)
        class FixtureHTTPS(FixtureHTTP):
            def request(self,method,path,body=None,headers=None):super().request(method,path,body,dict(headers or {},**{'X-Fixture-TLS':'yes'}))
        class Raw:
            def __enter__(self):return self
            def __exit__(self,*args):pass
        class TLS(Raw):
            def __init__(self,name):self.name=name
            def getpeercert(self,binary_form):return self.name.encode()
        class Context:
            def wrap_socket(self,raw,server_hostname):tls_names.append(server_hostname);return TLS(server_hostname)
        try:
            records=[]
            with patch('domain_checks.DirectHTTPS',FixtureHTTPS), patch('domain_checks.http.client.HTTPConnection',FixtureHTTP), patch('domain_checks.socket.create_connection',return_value=Raw()), patch('domain_checks.ssl.create_default_context',return_value=Context()):
                fingerprints=domain_checks(self.specs(),records)
                self.assertEqual(set(fingerprints),{'one.fixture.test','two.fixture.test'})
                self.assertEqual(len(set(fingerprints.values())),2)
                self.assertEqual(tls_names,['one.fixture.test','two.fixture.test'])
                wrong_redirect[0]=True
                with self.assertRaisesRegex(CheckFailure,'wrong_domain_redirect'):domain_checks(self.specs(),[])
                wrong_redirect[0]=False
                with patch('http_checks.DirectHTTPS',FixtureHTTPS):
                    try: fingerprints_root=web_checks('main.fixture.test',443,18443,18090,[],[], '', 'proxy.fixture.test')
                    except CheckFailure as error:
                        self.fail('admin_domain_request_failed: ' + str(error) + ' ' + json.dumps(error.details))
                self.assertEqual(set(fingerprints_root),{'443','18443'})
                self.assertEqual(tls_names[-2:],['main.fixture.test','main.fixture.test'])
                self.assertIn(('proxy.fixture.test','/api/vpn/status','https://proxy.fixture.test'),seen)
            self.assertEqual(set(row['domain'] for row in records),set(fingerprints))
            self.assertNotIn('secret',json.dumps(records))
            self.assertIn(('two.fixture.test','/api/private'),seen)
        finally:server.shutdown();server.server_close();thread.join(timeout=2)

    def fixture(self):
        summary,records,manifest=test_audit.RawObservationAuditTest().fixture()
        manifest.update({'admin_domain':'one.fixture.test','admin_path':'','domain_probes':self.specs()})
        # 后台主检查路径也随入口迁移；各业务相同路径按domain独立保留。
        for sample in records:
            for row in sample['http_checks']:
                if row['method']=='POST':row.update({'path':'/api/vpn/status','domain':'one.fixture.test'})
            sample['domain_checks']=[{'domain':d,'port':p,'path':path,'method':m,'actual':code,'expected':code}
                                     for (d,p,path,m),code in required_domain_http(self.specs()).items()]
            sample['domain_certificates']={'one.fixture.test':'b'*64,'two.fixture.test':'c'*64}
        return summary,records,manifest

    def test_auditor_rejects_host_collision_missing_cert_and_hidden_failure(self):
        summary,records,manifest=self.fixture()
        self.assertTrue(audit_records(summary,records,manifest)['review_passed'])
        bad=copy.deepcopy(records);bad[1]['domain_checks'][5]['domain']='one.fixture.test'
        self.assertIn('domain_inventory_mismatch_at_2',audit_records(summary,bad,manifest)['findings'])
        bad=copy.deepcopy(records);bad[1]['domain_checks'][-1]['actual']=200
        self.assertIn('domain_verdict_mismatch_at_2',audit_records(summary,bad,manifest)['findings'])
        bad=copy.deepcopy(records);del bad[1]['domain_certificates']['two.fixture.test']
        self.assertIn('domain_certificates_missing_at_2',audit_records(summary,bad,manifest)['findings'])
        bad=copy.deepcopy(records);bad[1]['domain_certificates']['two.fixture.test']=''
        self.assertIn('domain_certificate_invalid_at_2',audit_records(summary,bad,manifest)['findings'])
        bad=copy.deepcopy(records)
        next(row for row in bad[1]['http_checks'] if row['method']=='POST')['domain']='main.fixture.test'
        self.assertIn('admin_domain_mismatch_at_2',audit_records(summary,bad,manifest)['findings'])


if __name__=='__main__':unittest.main()
