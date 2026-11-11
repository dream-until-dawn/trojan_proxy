"""固定引擎+Mihomo真实TCP/UDP、域名解析后限制和DNS改变测试。"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import uuid
from gateway_probe import command

SERVER='trojan-runner:dev'
CLIENT='metacubex/mihomo@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c'
prefix='trojan-egress-'+uuid.uuid4().hex[:10]
network=None
containers=[]
client=None
report={'checks':{},'server_image':SERVER,'client_image':CLIENT,'limitations':['未替代Clash Verge/Clash Mi图形客户端验收。']}
mutation=os.environ.get('TROJAN_EGRESS_MUTATION')=='1'
def logs(cid):
    result=subprocess.run(['docker','logs',cid],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=10)
    return result.stdout
try:
    SERVER=json.loads(command(['docker','image','inspect',SERVER]))[0]['Id']
    report['server_image']=SERVER
    with tempfile.TemporaryDirectory(prefix='trojan-egress-') as directory:
        root=Path(directory)
        mount=str(root.resolve())+':/fixture'
        openssl=json.loads(command(['docker','image','inspect','alpine/openssl:latest']))[0]['Id']
        for name in ('trusted','untrusted'):
            command(['docker','run','--rm','--network','none','-v',mount,openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=vpn.test','-addext','subjectAltName=DNS:vpn.test','-keyout','/fixture/'+name+'.key','-out','/fixture/'+name+'.crt'])
        binary=str(Path('.work/vpn-integration.test').resolve())+':/probe:ro'
        command(['docker','run','--rm','--network','none','-v',mount,'-v',binary,'--entrypoint','/probe','trojan-control:m4','-test.run','^TestWriteEngineFixture$'])
        if mutation:
            config=json.loads((root/'server.json').read_text(encoding='utf-8'))
            config['route']['rules']=[rule for rule in config['route']['rules'] if 'ip_cidr' not in rule]
            (root/'server.json').write_text(json.dumps(config),encoding='utf-8')
        # 引擎只读固定证书路径；临时fixture与任何真实凭据完全无关。
        version=root/('a'*64);version.mkdir()
        (version/'fullchain.pem').write_bytes((root/'trusted.crt').read_bytes())
        (version/'private.key').write_bytes((root/'trusted.key').read_bytes())
        command(['docker','run','--rm','--network','none','-v',mount,'-v',str(root.resolve())+':/certificates:ro','--entrypoint','/usr/local/bin/trojan-engine',SERVER,'check','-c','/fixture/server.json'])
        network=command(['docker','network','create','--internal','--subnet','198.51.100.0/24',prefix])
        # 文档保留网段仅用于隔离Docker夹具，避免给产品引入任何私网白名单。
        backend_code='''import http.server,socket,threading
class H(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(200);self.end_headers();self.wfile.write(b"public-sentinel")
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",8001))
 while True:
  data,peer=s.recvfrom(2048);s.sendto(data,peer)
threading.Thread(target=udp,daemon=True).start()
http.server.HTTPServer(("0.0.0.0",8000),H).serve_forever()
'''
        backend=command(['docker','run','-d','--name',prefix+'-backend','--network',network,'--ip','198.51.100.20','--memory','64m','python:3.12-slim','python','-c',backend_code]);containers.append(backend)
        dns_code='''import socket,struct
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",53));counter=0
while True:
 data,peer=s.recvfrom(2048);offset=12;labels=[]
 while data[offset]:
  size=data[offset];labels.append(data[offset+1:offset+1+size].decode());offset+=size+1
 offset+=1;kind=struct.unpack("!H",data[offset:offset+2])[0];name=".".join(labels)
 ip="198.51.100.20"
 if name=="private.test":ip="127.0.0.1"
 if name=="rebind.test" and kind==1:
  counter+=1
  if counter>1:ip="127.0.0.1"
 question=data[12:offset+4];count=1 if kind==1 else 0
 answer=b""
 if count:answer=b"\\xc0\\x0c"+struct.pack("!HHIH",1,1,0,4)+socket.inet_aton(ip)
 s.sendto(data[:2]+struct.pack("!HHHHH",0x8180,1,count,0,0)+question+answer,peer)
'''
        dns=command(['docker','run','-d','--name',prefix+'-dns','--network',network,'--ip','198.51.100.53','--memory','64m','python:3.12-slim','python','-c',dns_code]);containers.append(dns)
        server=command(['docker','run','-d','--name',prefix+'-server','--network',network,'--network-alias','vpn.test','--ip','198.51.100.10',
            '--memory','128m','--cap-drop','ALL','--security-opt','no-new-privileges','-v',mount+':ro','-v',str(root.resolve())+':/certificates:ro','--entrypoint','/usr/local/bin/trojan-engine',SERVER,'run','-c','/fixture/server.json']);containers.append(server)
        sentinel=command(['docker','run','-d','--name',prefix+'-private-sentinel','--network','container:'+server,'--memory','64m','python:3.12-slim','python','-c',backend_code]);containers.append(sentinel)
        for phase,password,trust in [('good','fixture-only-password-0123456789abcdef','trusted'),('bad-password','incorrect-password','trusted'),('bad-ca','fixture-only-password-0123456789abcdef','untrusted')]:
            config={'mixed-port':7890,'allow-lan':True,'bind-address':'0.0.0.0','mode':'rule','proxies':[{'name':'probe','type':'trojan','server':'vpn.test','port':18443,'sni':'vpn.test','password':password,'skip-cert-verify':False,'udp':True}],'rules':['MATCH,probe']}
            (root/'client.json').write_text(json.dumps(config),encoding='utf-8')
            client=command(['docker','run','-d','--name',prefix+'-client-'+phase,'--network',network,'--memory','128m','--cap-drop','ALL',
                '-e','SSL_CERT_FILE=/fixture/'+trust+'.crt','-v',mount+':ro',CLIENT,'-f','/fixture/client.json','-d','/tmp']);containers.append(client)
            result=subprocess.run(['docker','run','--rm','--network','container:'+client,'--memory','128m','--cap-drop','ALL','--read-only','-v',binary,
                '-e','TROJAN_VPN_PHASE='+phase,'--entrypoint','/probe','trojan-control:m4','-test.run','^TestRealTrojanEgressAndUDP$','-test.v','-test.timeout','45s'],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=60)
            report['checks'][phase]={'exit_code':result.returncode,'output':result.stdout}
            if mutation:
                if result.returncode==0 or '目的地址保护失效 127.0.0.1 public-sentinel' not in result.stdout:raise RuntimeError('删除IP限制没有触发指定私网哨兵断言')
                report['expected_mutation_failure']='目的地址保护失效 127.0.0.1 public-sentinel'
                break
            if result.returncode:raise RuntimeError('真实VPN阶段失败: '+phase)
            if phase=='bad-ca' and 'certificate' not in logs(client).lower():raise RuntimeError('没有观察到证书拒绝原因')
            command(['docker','rm','-f',client]);containers.remove(client);client=None
except Exception as error:
    report['error']=str(error)
    report['logs']={cid:logs(cid)[-2500:] for cid in containers}
finally:
    for cid in reversed(containers):command(['docker','rm','-f',cid])
    if network:command(['docker','network','rm',network])
report['passed']='error' not in report
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
