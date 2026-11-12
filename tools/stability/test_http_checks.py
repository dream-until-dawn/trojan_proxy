import http.client
import http.server
import json
import socketserver
import threading
import unittest
from unittest.mock import patch
from checks import CheckFailure
from http_checks import check_response, response_category, extra_https_checks, validate_https_routes


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class HTTPDiagnosticsTest(unittest.TestCase):
    def request(self, status, body, expected):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status);self.send_header('Set-Cookie','secret-cookie-sentinel');self.end_headers();self.wfile.write(body)
            def log_message(self, *args): pass
        server=Server(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.daemon=True;thread.start()
        records=[]
        try:
            port=server.server_port
            connection=http.client.HTTPConnection('127.0.0.1',port,timeout=2)
            check_response(connection,port,'/healthz','GET','localhost',expected,records)
        except CheckFailure as error:
            self.assertEqual(error.details['actual'],status)
            self.assertEqual(error.details['expected'],expected)
            self.assertEqual(error.details['port'],port)
            self.assertEqual(error.details['path'],'/healthz')
            return records,error
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)
        return records,None

    def test_real_http_positive_and_status_mismatch_keep_exact_endpoint(self):
        records,error=self.request(200,b'healthy',200)
        self.assertIsNone(error);self.assertEqual(records[0]['actual'],200)
        records,error=self.request(503,b'secret-body-sentinel',200)
        self.assertIsNotNone(error);self.assertEqual(str(error),'unexpected_http_status')
        self.assertGreaterEqual(records[0]['elapsed_ms'],0)
        self.assertNotIn('secret',json.dumps(records)+json.dumps(error.details))

    def test_host_denial_is_classified_without_retaining_raw_body(self):
        body=json.dumps({'error':'访问地址不被允许'}).encode()
        records,error=self.request(421,body,401)
        self.assertEqual(records[0]['response_category'],'host_not_allowed')
        self.assertEqual(error.details['response_category'],'host_not_allowed')
        for body in [b'{"error":{"secret":"value"}}',b'not JSON',b'{"error":"secret"}']:
            self.assertEqual(response_category(body),'other')

    def test_optional_route_contract_rejects_bad_metadata(self):
        good = {'port':8001,'path':'/api/overview','expected':401}
        self.assertEqual(validate_https_routes([good]),[good])
        for value in [None, {}, [dict(good,port=True)], [dict(good,port=80)], [dict(good,path='/login?token=secret')], [dict(good,expected=201)], [good,good]]:
            with self.assertRaises(CheckFailure): validate_https_routes(value)

    def test_additional_route_keeps_host_port_and_exact_failure(self):
        captured=[]
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                captured.append(self.headers['Host']);self.send_response(401 if self.path=='/api/overview' else 503);self.end_headers()
            def log_message(self,*args): pass
        server=Server(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever);thread.daemon=True;thread.start()
        try:
            records=[]
            # 这里只替换测试夹具传输以核验HTTP契约；生产DirectHTTPS仍严格校验TLS。
            with patch('http_checks.DirectHTTPS',side_effect=lambda domain,port,timeout:http.client.HTTPConnection('127.0.0.1',port,timeout=timeout)):
                extra_https_checks('fixture.invalid',[{'port':server.server_port,'path':'/api/overview','expected':401}],records)
                with self.assertRaises(CheckFailure) as failure:
                    extra_https_checks('fixture.invalid',[{'port':server.server_port,'path':'/login','expected':200}],records)
            self.assertEqual(captured,['fixture.invalid:'+str(server.server_port)]*2)
            self.assertEqual(failure.exception.details['actual'],503)
            self.assertEqual(failure.exception.details['path'],'/login')
            self.assertEqual([row['actual'] for row in records],[401,503])
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)


if __name__=='__main__':unittest.main()
