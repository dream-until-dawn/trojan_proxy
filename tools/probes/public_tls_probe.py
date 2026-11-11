"""临时复用已有证书测试8007可达性；不导出私钥、不修改现有容器。"""
import json
import ssl
import socket
import time
import uuid
from gateway_probe import command, free_port, request, running_snapshot

before=running_snapshot()
cid=None
try:
    admin=free_port()
    cid=command(['docker','run','-d','--name','trojan-public-tls-'+uuid.uuid4().hex[:10],
        '--network','host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','128m','--cpus','0.5','--tmpfs','/data','--tmpfs','/config',
        '-v','/mnt/trojan/cert/qin-xin.top:/certs:ro',
        '-e','CADDY_ADMIN=127.0.0.1:{}'.format(admin),
        'caddy@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9','caddy','run'])
    for i in range(50):
        try:
            if request(admin,'/config/')[0]==200: break
        except OSError: pass
        time.sleep(.2)
    config={'admin':{'listen':'127.0.0.1:{}'.format(admin)},'apps':{
        'tls':{'certificates':{'load_files':[{'certificate':'/certs/fullchain.cer','key':'/certs/private.key'}]}},
        'http':{'servers':{'probe':{'listen':[':8007'],'automatic_https':{'disable':True},
            'tls_connection_policies':[{}],
            'routes':[{'match':[{'host':['qin-xin.top']}],'handle':[{'handler':'static_response','body':'public-tls-probe-ok'}]}]}}}}}
    status,body=request(admin,'/load',config)
    if status!=200: raise RuntimeError(body)
    with socket.create_connection(('127.0.0.1',8007),timeout=4) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname='qin-xin.top') as tls:
            tls.sendall(b'GET / HTTP/1.1\r\nHost: qin-xin.top\r\nConnection: close\r\n\r\n')
            data=b''
            while True:
                block=tls.recv(4096)
                if not block: break
                data+=block
            assert b'public-tls-probe-ok' in data
    print(json.dumps({'ready':True,'port':8007,'local_tls_verified':True,'window_seconds':90}),flush=True)
    time.sleep(90)
finally:
    if cid: command(['docker','rm','-f',cid])
    after=running_snapshot()
    print(json.dumps({'cleaned':True,'existing_containers_unchanged':all(after.get(k)==v for k,v in before.items())}),flush=True)
