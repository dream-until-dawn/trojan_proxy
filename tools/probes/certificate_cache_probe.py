"""真实Caddy内部CA证书缓存适配与非root原子发布，不申请公共证书。"""
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
from gateway_probe import command

prefix='trojan-cert-cache-'+uuid.uuid4().hex[:10]
volumes=[]
cid=None
report={'public_ca_used':False}
try:
    cache=command(['docker','volume','create',prefix+'-cache']);volumes.append(cache)
    published=command(['docker','volume','create',prefix+'-published']);volumes.append(published)
    command(['docker','run','--rm','--network','none','-v',cache+':/cache','-v',published+':/published',
        'alpine:3.22','sh','-c','chown 10001:10001 /cache /published && chmod 0750 /cache /published'])
    with tempfile.TemporaryDirectory(prefix='trojan-ca-config-') as directory:
        path=Path(directory)/'Caddyfile'
        path.write_text('{\n admin off\n auto_https disable_redirects\n skip_install_trust\n renew_interval 1s\n renewal_window_ratio 0.8\n}\nhttps://probe.test:18443 {\n tls {\n  issuer internal {\n   lifetime 30s\n  }\n }\n respond "certificate-cache-probe"\n}\n',encoding='utf-8')
        cid=command(['docker','run','-d','--name',prefix,'--user','10001:10001','--read-only','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','128m','--cpus','0.5',
            '-v',str(path.resolve())+':/etc/caddy/Caddyfile:ro','-v',cache+':/data','--tmpfs','/config','--tmpfs','/tmp',
            'caddy@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9'])
        ready=False
        for _ in range(50):
            result=subprocess.run(['docker','exec',cid,'test','-f','/data/caddy/certificates/local/probe.test/probe.test.crt'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
            if result.returncode==0:ready=True;break
            time.sleep(.2)
        if not ready:raise RuntimeError('内部CA证书缓存未生成')
        binary=str(Path('.work/certificates-integration.test').resolve())+':/probe:ro'
        before=command(['docker','exec',cid,'sha256sum','/data/caddy/certificates/local/probe.test/probe.test.crt']).split()[0]
        report['phases']={}
        for phase in ('first','renewal'):
            if phase=='renewal':
                changed=False
                for _ in range(30):
                    time.sleep(1)
                    after=command(['docker','exec',cid,'sha256sum','/data/caddy/certificates/local/probe.test/probe.test.crt']).split()[0]
                    if after!=before: changed=True;break
                if not changed:raise RuntimeError('短期证书未按计划自动续期')
            result=subprocess.run(['docker','run','--rm','--network','none','--read-only','--user','10001:10001',
                '--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--tmpfs','/tmp',
                '-v',binary,'-v',cache+':/cache:ro','-v',published+':/published','-e','TROJAN_CERT_PHASE='+phase,
                '--entrypoint','/probe','trojan-control:m4','-test.run','TestCaddyManagedCacheAndPublish','-test.v','-test.timeout','30s'],
                stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=60)
            report['phases'][phase]={'exit_code':result.returncode,'output':result.stdout}
            if result.returncode:raise RuntimeError('证书缓存适配或发布测试失败: '+phase)
        report['renewal_changed_certificate']=True
except Exception as error:
    report['error']=str(error)
    if cid:report['logs']=command(['docker','logs',cid])[-4000:]
finally:
    if cid:command(['docker','rm','-f',cid])
    for volume in reversed(volumes):command(['docker','volume','rm',volume])
report['passed']='error' not in report
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
