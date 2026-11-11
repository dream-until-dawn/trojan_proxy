"""隔离网络真实HTTP-01签发、短期续期和实际握手；不访问公共CA。"""
import json
from pathlib import Path
import subprocess
import tempfile
import uuid
from gateway_probe import command

CADDY='caddy@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9'
PEBBLE='ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef'
prefix='trojan-acme-'+uuid.uuid4().hex[:10]
network=None
volumes=[]
containers=[]
report={'public_ca_used':False,'challenge_validation_skipped':False,'pebble_image':PEBBLE,'caddy_image':CADDY}
try:
    network=command(['docker','network','create','--internal',prefix])
    for kind in ('socket','fixture','cache','published'):
        volumes.append(command(['docker','volume','create',prefix+'-'+kind]))
    sock,fixture,cache,published=volumes
    command(['docker','run','--rm','--network','none','-v',sock+':/socket','-v',cache+':/cache','-v',published+':/published',
        'alpine:3.22','sh','-c','chown 0:10001 /socket && chmod 0770 /socket && chown 10001:10001 /cache /published && chmod 0750 /cache /published'])
    openssl=json.loads(command(['docker','image','inspect','alpine/openssl:latest']))[0]['Id']
    command(['docker','run','--rm','--network','none','-v',fixture+':/fixture',openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
        '-subj','/CN=pebble','-addext','subjectAltName=DNS:pebble','-keyout','/fixture/key.pem','-out','/fixture/ca.pem'])
    caddy=command(['docker','run','-d','--name',prefix+'-caddy','--network',network,'--user','10001:10001','--read-only','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--memory','128m','--cpus','1','-v',sock+':/run/caddy','-v',cache+':/data',
        '-v',fixture+':/fixture:ro','--tmpfs','/config','-e','CADDY_ADMIN=unix//run/caddy/admin.sock|0660',CADDY,'caddy','run'])
    containers.append(caddy)
    caddy_ip=next(iter(json.loads(command(['docker','inspect',caddy]))[0]['NetworkSettings']['Networks'].values()))['IPAddress']
    with tempfile.TemporaryDirectory(prefix='trojan-pebble-') as directory:
        path=Path(directory)/'pebble.json'
        path.write_text(json.dumps({'pebble':{'listenAddress':'0.0.0.0:14000','managementListenAddress':'0.0.0.0:15000',
            'certificate':'/fixture/ca.pem','privateKey':'/fixture/key.pem','httpPort':80,'tlsPort':443,
            'profiles':{'default':{'description':'bounded lifecycle fixture','validityPeriod':30}}}}),encoding='utf-8')
        pebble=command(['docker','run','-d','--name',prefix+'-pebble','--network',network,'--network-alias','pebble',
            '--add-host','probe.test:'+caddy_ip,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--memory','128m','--cpus','1','-e','PEBBLE_VA_NOSLEEP=1','-e','PEBBLE_WFE_NONCEREJECT=0',
            '-v',str(path.resolve())+':/pebble.json:ro','-v',fixture+':/fixture:ro',PEBBLE,'-config','/pebble.json','-strict'])
        containers.append(pebble)
        binary=str(Path('.work/gateway-integration.test').resolve())+':/probe:ro'
        result=subprocess.run(['docker','run','--rm','--network','container:'+caddy,'--user','10001:10001','--read-only',
            '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--tmpfs','/tmp','-v',binary,
            '-v',sock+':/run/caddy:ro','-v',fixture+':/fixture:ro','-v',cache+':/cache:ro','-v',published+':/published',
            '--entrypoint','/probe','trojan-control:m4','-test.run','^TestRealHTTP01AndRenewal$','-test.v','-test.timeout','90s'],
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=100)
        report['test']={'exit_code':result.returncode,'output':result.stdout}
        if result.returncode:raise RuntimeError('ACME生命周期验收失败')
        logs=command(['docker','logs',pebble])
        if 'Attempting to validate w/ HTTP:' not in logs:raise RuntimeError('缺少真实HTTP-01挑战记录')
        report['http01_challenge_observed']=True
except Exception as error:
    report['error']=str(error)
    report['logs']={cid:command(['docker','logs',cid])[-5000:] for cid in containers}
finally:
    for cid in reversed(containers):command(['docker','rm','-f',cid])
    for volume in reversed(volumes):command(['docker','volume','rm',volume])
    if network:command(['docker','network','rm',network])
report['passed']='error' not in report
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
