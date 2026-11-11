"""从实际IP做可信TLS与管理API反向验收，绕开本机Fake-IP但不跳过证书校验。"""
import argparse
import hashlib
import http.client
import json
import socket
import ssl

parser=argparse.ArgumentParser()
parser.add_argument('--ip',default='47.82.112.245')
parser.add_argument('--domain',default='qin-xin.top')
parser.add_argument('--port',type=int,default=8007)
args=parser.parse_args()
origin='https://{}:{}'.format(args.domain,args.port)
wrong_origin='https://{}:{}'.format(args.domain,args.port+1 if args.port<65535 else args.port-1)
report={'origin':origin,'checks':{},'passed':False}

class DirectHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw=socket.create_connection((args.ip,args.port),timeout=8)
        self.sock=ssl.create_default_context().wrap_socket(raw,server_hostname=args.domain)
        report['certificate_sha256']=hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()

try:
    cases=[('GET','/',None,200),('GET','/vpn.js',None,200),('GET','/traffic.js',None,200),
           ('POST','/api/vpn/status',origin,401),('POST','/api/vpn/export',origin,401),
           ('POST','/api/traffic/live',origin,401),('POST','/api/traffic/dashboard',origin,401),
           ('POST','/api/traffic/clear',origin,401),
           ('POST','/api/traffic/dashboard',wrong_origin,403),
           ('POST','/api/vpn/export',wrong_origin,403)]
    for method,path,source,expected in cases:
        connection=DirectHTTPS(args.domain,args.port,timeout=8)
        try:
            headers={'Host':args.domain+':'+str(args.port)}
            if source:headers.update({'Origin':source,'Content-Type':'application/json'})
            connection.request(method,path,body='{}' if method=='POST' else None,headers=headers)
            response=connection.getresponse();body=response.read(200000)
            key=method+' '+path+(' wrong-origin' if source and source!=origin else '')
            report['checks'][key]={'status':response.status,'cache_control':response.getheader('Cache-Control')}
            if response.status!=expected:raise RuntimeError('公网状态码不符合预期: '+key)
            if response.getheader('Cache-Control')!='no-store':raise RuntimeError('管理响应缺少no-store')
            if response.getheader('X-Robots-Tag')!='noindex, nofollow, noarchive, nosnippet':raise RuntimeError('管理响应缺少爬虫排除声明')
            if path=='/' and b'id="vpn-status"' not in body:raise RuntimeError('实际页面尚未加载VPN管理')
        finally:connection.close()
    report['passed']=True
except Exception as error:report['error']=str(error)
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
