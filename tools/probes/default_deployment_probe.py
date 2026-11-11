"""隔离网络命名空间中的默认Compose全流程，所有卷和账户均为一次性夹具。"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

root=Path(__file__).resolve().parents[2]
prefix='trojan-default-'+uuid.uuid4().hex[:10]
environment=dict(os.environ)
for key,value in [('TROJAN_CONTROL_IMAGE','trojan-control:final'),('TROJAN_RUNNER_IMAGE','trojan-runner:final'),('TROJAN_GATEWAY_IMAGE','trojan-gateway:dev')]:environment.setdefault(key,value)
report={'passed':False,'scope':'disposable isolated Compose; no real server or public CA','checks':{}}
backend=None
restore=None

def command(args,timeout=60,allow_failure=False):
    result=subprocess.run([str(v) for v in args],cwd=root,env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=timeout)
    if result.returncode and not allow_failure:raise RuntimeError('command failed '+str(args[:4])+': '+result.stdout[-1800:])
    return result

with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
    override=Path(temporary)/'override.json'
    services={'lab':{'image':'alpine:3.22','command':['sleep','86400'],'network_mode':'none','read_only':True,'cap_drop':['ALL'],'sysctls':{'net.ipv4.ip_unprivileged_port_start':'1024'}}}
    for service in ('prepare','control','vpn-runner','admin-gateway'):services[service]={'network_mode':'service:lab'}
    services['control']['volumes']=['fixture-public:/srv/public/public:ro']
    override.write_text(json.dumps({'services':services,'volumes':{'fixture-public':{}}}),encoding='utf-8')
    compose=['docker','compose','-p',prefix,'-f',root/'deploy/compose.yaml','-f',override]
    try:
        resolved=json.loads(command(compose+['config','--format','json']).stdout)
        if os.environ.get('TROJAN_GATEWAY_CACHE_MUTATION')=='1':
            # 新Compose会拒绝重复target，故直接替换成可写临时盘；
            # 必须由持久性断言发现，不能让解析器或UID权限提前掩盖该断言。
            gateway=resolved['services']['admin-gateway']
            gateway['volumes']=[v for v in gateway['volumes'] if v['target']!='/data']
            gateway['tmpfs']=['/data:uid=10001,gid=10001,mode=0700','/config:uid=10001,gid=10001,mode=0700','/tmp:uid=10001,gid=10001,mode=0700']
            override.write_text(json.dumps(resolved),encoding='utf-8')
            compose=['docker','compose','-p',prefix,'-f',override]
        command(compose+['up','-d','lab'])
        lab=command(compose+['ps','-q','lab']).stdout.strip()
        public=resolved['volumes']['fixture-public']['name']
        data=resolved['volumes']['control-data']['name']
        cache=resolved['volumes']['caddy-data']['name']
        command(['docker','run','--rm','--network','none','-v',public+':/fixture','alpine:3.22','sh','-c','printf readonly-file-sentinel > /fixture/download.txt && chmod 0755 /fixture && chmod 0644 /fixture/download.txt'])
        backend=command(['docker','run','-d','--name',prefix+'-backend','--network','container:'+lab,'--user','10001:10001','--read-only','--cap-drop','ALL','python:3.12-slim','python','-c',
            'import http.server\nclass H(http.server.BaseHTTPRequestHandler):\n def do_GET(self):\n  self.send_response(200);self.end_headers();self.wfile.write(b"upstream-sentinel")\n def log_message(self,*args):pass\nhttp.server.HTTPServer(("127.0.0.1",19000),H).serve_forever()']).stdout.strip()
        command(compose+['up','-d'])

        def ready(setup=False):
            deadline=time.time()+30
            port=18092 if setup else 18090
            while time.time()<deadline:
                result=command(compose+['exec','-T','control','wget','-q','-T','2','-O','/dev/null','http://127.0.0.1:'+str(port)+'/healthz'],allow_failure=True)
                if result.returncode==0:return
                time.sleep(.3)
            raise RuntimeError('expected management listener not ready: '+str(port))

        ready(True)
        # 镜像USER或Compose声明不足以证明降权，独立读取最终PID 1的内核状态。
        for service,uid,capability in [('admin-gateway',10001,0x400),('control',10001,0),('vpn-runner',10002,0)]:
            process=command(compose+['exec','-T',service,'cat','/proc/1/status']).stdout
            fields=dict(line.split(':',1) for line in process.splitlines() if ':' in line)
            if [int(value) for value in fields['Uid'].split()]!=[uid]*4:raise RuntimeError('runtime UID did not match isolated role: '+service)
            if [int(value) for value in fields['Gid'].split()]!=[10001]*4:raise RuntimeError('runtime GID did not match isolated role: '+service)
            for key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'):
                if int(fields[key],16)!=capability:raise RuntimeError('runtime capability set too wide or missing: '+service+' '+key)
            if fields['NoNewPrivs'].strip()!='1':raise RuntimeError('runtime no-new-privileges missing: '+service)
        report['checks']['actual_uid_gid_all_capability_sets_and_no_new_privs']=True
        write_cache=command(compose+['exec','-T','--user','10001:10001','admin-gateway','sh','-c','umask 077; printf persistent-cache-sentinel > /data/.persistence-probe'],allow_failure=True)
        if write_cache.returncode:raise RuntimeError('gateway cache is not writable as runtime UID')
        read_cache=command(['docker','run','--rm','--network','none','--user','10001:10001','--read-only','--cap-drop','ALL','-v',cache+':/cache:ro','alpine:3.22','cat','/cache/.persistence-probe'],allow_failure=True)
        if read_cache.returncode or read_cache.stdout.strip()!='persistent-cache-sentinel':raise RuntimeError('gateway cache mount is not persistent')
        negative=command(compose+['exec','-T','control','proxyctl','setup-token'],allow_failure=True)
        if negative.returncode==0 or '交互终端' not in negative.stdout:raise RuntimeError('setup token accepted non-TTY output')
        report['checks']['setup_token_no_tty_rejected']=True
        binary=str((root/'.work/deployment-integration.test').resolve())+':/probe:ro'

        def flow(phase):
            result=command(['docker','run','--rm','--network','container:'+lab,'--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','192m','--tmpfs','/tmp',
                '-v',data+':/data','-v',binary,'-e','TROJAN_DISPOSABLE_COMPOSE_TEST=1','-e','TROJAN_COMPOSE_PHASE='+phase,'--entrypoint','/probe',environment['TROJAN_CONTROL_IMAGE'],'-test.run','^TestDisposableComposeFlow$','-test.v','-test.timeout','45s'])
            report['checks'][phase]={'passed':True,'output':result.stdout}

        flow('first')
        command(compose+['up','-d'])
        ready()
        flow('verify')
        report['checks']['repeated_up_preserved_web_settings']=True
        command(compose+['up','-d','--force-recreate','--no-deps','control','vpn-runner','admin-gateway'])
        ready()
        flow('verify')
        report['checks']['container_recreation_preserved_account_routes_settings']=True
        if command(compose+['exec','-T','--user','10001:10001','admin-gateway','cat','/data/.persistence-probe']).stdout.strip()!='persistent-cache-sentinel':raise RuntimeError('gateway cache disappeared after recreation')
        report['checks']['cache_persists_across_container_recreation']=True
        restore=command(['docker','volume','create',prefix+'-restore']).stdout.strip()
        command(['docker','run','--rm','--network','none','-v',restore+':/restore','alpine:3.22','sh','-c','chown 10001:10001 /restore && chmod 0700 /restore'])
        command(['docker','run','--rm','--network','container:'+lab,'--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','192m','--tmpfs','/tmp',
            '-v',data+':/data','-v',restore+':/restore','-v',binary,'-e','TROJAN_DISPOSABLE_COMPOSE_TEST=1','--entrypoint','/probe',environment['TROJAN_CONTROL_IMAGE'],'-test.run','^TestDisposableLiveBackupAndColdRestoreGate$','-test.v','-test.timeout','30s'])
        report['checks']['live_control_lock_online_backup_and_cold_restore_auth_gate']=True
        report['checks']['unprivileged_port_start_1024_nonroot_gateway']=True
        report['passed']=True
    except Exception as error:
        report['error']=str(error)
        report['logs']=command(compose+['logs','--no-color','--tail','30'],allow_failure=True).stdout[-6000:]
    finally:
        if backend:command(['docker','rm','-f',backend],allow_failure=True)
        if restore:command(['docker','volume','rm',restore],allow_failure=True)
        cleanup=command(compose+['down','-v','--remove-orphans'],allow_failure=True)
        report['disposable_project_cleanup']=cleanup.returncode==0
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] and report['disposable_project_cleanup'] else 1)
