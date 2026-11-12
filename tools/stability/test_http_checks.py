import http.client
import http.server
import json
import socketserver
import threading
import unittest
from checks import CheckFailure
from http_checks import check_response, response_category


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


if __name__=='__main__':unittest.main()
