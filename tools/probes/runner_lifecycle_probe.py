"""真实非root执行器：check、轮换、回退、进程退出和容器重启。"""
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from images import control_image, openssl_image
from gateway_probe import command

prefix='trojan-runner-'+uuid.uuid4().hex[:10]
volumes=[]
runner=None
report={'phases':{}}
try:
    for name in ('socket','certificates'):volumes.append(command(['docker','volume','create',prefix+'-'+name]))
    socket,certs=volumes
    command(['docker','run','--rm','--network','none','-v',socket+':/socket','-v',certs+':/certificates','alpine:3.22','sh','-c',
        'chown 10002:10001 /socket && chmod 0770 /socket && chown 0:10001 /certificates && chmod 0750 /certificates'])
    openssl=openssl_image()
    for letter in ('a','b'):
        version=letter*64
        command(['docker','run','--rm','--network','none','-v',certs+':/certificates','alpine:3.22','mkdir','/certificates/'+version])
        command(['docker','run','--rm','--network','none','-v',certs+':/certificates',openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=probe.test','-addext','subjectAltName=DNS:probe.test','-keyout','/certificates/'+version+'/private.key','-out','/certificates/'+version+'/fullchain.pem'])
    command(['docker','run','--rm','--network','none','-v',certs+':/certificates','alpine:3.22','sh','-c',
        'mkdir /certificates/'+'c'*64+' /certificates/'+'d'*64+' && cp /certificates/'+'a'*64+'/fullchain.pem /certificates/'+'c'*64+'/fullchain.pem && cp /certificates/'+'b'*64+'/private.key /certificates/'+'c'*64+'/private.key && cp /certificates/'+'a'*64+'/private.key /certificates/'+'d'*64+'/private.key'])
    binary=str(Path('.work/runner-integration.test').resolve())+':/probe:ro'
    command(['docker','run','--rm','--network','none','--user','0:0','-v',binary,'-v',certs+':/certificates','--entrypoint','/probe',
        control_image(),'-test.run','^TestWriteExpiredFixture$'])
    command(['docker','run','--rm','--network','none','-v',certs+':/certificates','alpine:3.22','sh','-c',
        'chown -R 0:10001 /certificates && find /certificates -type d -exec chmod 0750 {} + && find /certificates -type f -exec chmod 0640 {} +'])
    runner=command(['docker','run','-d','--name',prefix,'--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--memory','192m','--cpus','1','--pids-limit','64','-v',socket+':/run/vpn','-v',certs+':/certificates:ro',
        os.environ.get('TROJAN_RUNNER_IMAGE','trojan-runner:dev'),'--config','/certificates/proxy.json'])
    binary=str(Path('.work/runner-integration.test').resolve())+':/probe:ro'
    for phase in ('first','crash','restart'):
        if phase=='crash':
            pid=command(['docker','exec',runner,'pidof','trojan-engine'])
            if not re.fullmatch(r'[0-9]+',pid):raise RuntimeError('不能唯一识别本执行器子进程')
            command(['docker','exec',runner,'kill','-9',pid])
        if phase=='restart':command(['docker','restart',runner])
        result=subprocess.run(['docker','run','--rm','--network','container:'+runner,'--read-only','--user','10001:10001',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','-v',binary,'-v',socket+':/run/vpn:ro','-v',certs+':/certificates:ro',
            '-e','TROJAN_RUNNER_PHASE='+phase,'--entrypoint','/probe',control_image(),'-test.run','^TestRealRunnerLifecycle$','-test.v','-test.timeout','50s'],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=60)
        report['phases'][phase]={'exit_code':result.returncode,'output':result.stdout}
        if result.returncode:raise RuntimeError('真实执行器阶段失败: '+phase)
except Exception as error:
    report['error']=str(error)
    if runner:
        result=subprocess.run(['docker','logs',runner],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=10)
        report['runner_logs']=result.stdout[-3000:]
finally:
    if runner:command(['docker','rm','-f',runner])
    for volume in reversed(volumes):command(['docker','volume','rm',volume])
report['passed']='error' not in report
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
