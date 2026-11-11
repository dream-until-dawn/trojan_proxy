"""真实网关跨容器重启验收，资源均使用唯一前缀并限定在本轮范围。"""
import json
import os
from pathlib import Path
import subprocess
import uuid
from gateway_probe import command
from images import gateway_image, container_logs

prefix='trojan-gateway-lifecycle-'+uuid.uuid4().hex[:10]
volumes=[]
gateway=None
report={'phases':{},'limitations':['测试使用临时证书和临时数据，不等于生产证书续期验收。']}
gateway_target=gateway_image()
report['gateway_image']=gateway_target
try:
    for kind in ('socket','certs','state','public'):
        volumes.append(command(['docker','volume','create',prefix+'-'+kind]))
    sock,certs,state,public=volumes
    command(['docker','run','--rm','--network','none','-v',sock+':/socket','-v',state+':/state','-v',public+':/public',
        'alpine:3.22','sh','-c','chown 0:10001 /socket && chmod 0770 /socket && chown 10001:10001 /state /public && chmod 0700 /state /public'])
    openssl=json.loads(command(['docker','image','inspect','alpine/openssl:latest']))[0]['Id']
    command(['docker','run','--rm','--network','none','-v',certs+':/certs',openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,DNS:localhost.test','-keyout','/certs/private.key','-out','/certs/fullchain.cer'])
    command(['docker','run','--rm','--network','none','-v',certs+':/certs','alpine:3.22','sh','-c','chown -R 0:10001 /certs && chmod 0750 /certs && chmod 0640 /certs/*'])
    gateway=command(['docker','run','-d','--name',prefix+'-caddy','--user','0:10001','--read-only','--cap-drop','ALL',
        '--cap-add','SETUID','--cap-add','SETGID','--cap-add','SETPCAP','--cap-add','NET_BIND_SERVICE',
        '--security-opt','no-new-privileges','--memory','128m','--cpus','0.5',
        '--mount','type=volume,source='+sock+',target=/run/caddy,volume-nocopy','-v',certs+':/certs:ro','-v',certs+':/certificates/test:ro','--tmpfs','/data','--tmpfs','/config',
        '-e','CADDY_ADMIN=unix//run/caddy/admin.sock|0660',
        gateway_target,'caddy','run'])
    binary=str(Path(os.environ.get('TROJAN_GATEWAY_PROBE_BINARY','.work/gateway-integration.test')).resolve())+':/probe:ro'
    for phase in ('first','restart'):
        if phase=='restart':command(['docker','restart',gateway])
        result=subprocess.run(['docker','run','--rm','--network','container:'+gateway,'--user','10001:10001',
            '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--cpus','1',
            '--tmpfs','/tmp','-v',binary,'-v',sock+':/run/caddy:ro','-v',state+':/state','-v',public+':/public','-v',certs+':/certs:ro',
            '-e','TROJAN_GATEWAY_PHASE='+phase,'--entrypoint','/probe','trojan-control:m4',
            '-test.run','TestRealGatewayLifecycle','-test.v','-test.timeout','60s'],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
        report['phases'][phase]={'exit_code':result.returncode,'output':result.stdout}
        if result.returncode:raise RuntimeError('生命周期阶段失败: '+phase)
except Exception as error:
    report['error']=str(error)
    if gateway:report['gateway_logs']=container_logs(gateway)[-4000:]
finally:
    if gateway:command(['docker','rm','-f',gateway])
    for volume in reversed(volumes):command(['docker','volume','rm',volume])
report['passed']=len(report['phases'])==2 and 'error' not in report
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
