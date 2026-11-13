"""一次性真实网关：正式编译器、HTTP/HTTPS/后台/错误/前缀、落盘前脱敏和空闲时间轮转。"""
import json,os,subprocess,uuid
from pathlib import Path
from images import control_image,gateway_image,openssl_image,container_logs
from gateway_probe import command

prefix='trojan-access-'+uuid.uuid4().hex[:10]
volumes=[];gateway=None;report={'passed':False}
try:
 for kind in ('socket','certs','state','data'):
  volumes.append(command(['docker','volume','create',prefix+'-'+kind]))
 sock,certs,state,data=volumes
 command(['docker','run','--rm','--network','none','-v',sock+':/socket','-v',state+':/state','-v',data+':/data','alpine:3.22','sh','-c','chown 0:10001 /socket && chmod 0770 /socket && chown 10001:10001 /state /data && chmod 0700 /state /data'])
 command(['docker','run','--rm','--network','none','-v',certs+':/certs',openssl_image(),'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout','/certs/private.key','-out','/certs/fullchain.cer','-subj','/CN=localhost.test','-addext','subjectAltName=DNS:localhost.test'])
 command(['docker','run','--rm','--network','none','-v',certs+':/certs','alpine:3.22','sh','-c','chown 0:10001 /certs/* && chmod 0640 /certs/*'])
 gateway=command(['docker','run','-d','--name',prefix+'-gateway','--user','0:10001','--read-only','--cap-drop','ALL','--cap-add','SETUID','--cap-add','SETGID','--cap-add','SETPCAP','--cap-add','NET_BIND_SERVICE','--security-opt','no-new-privileges','--memory','192m',
  '-v',sock+':/run/caddy','-v',certs+':/certs:ro','-v',certs+':/certificates/test:ro','-v',data+':/data','--tmpfs','/config:uid=10001,gid=10001,mode=0700','-e','CADDY_ADMIN=unix//run/caddy/admin.sock|0660',gateway_image(),'caddy','run'])
 binary=str(Path(os.environ.get('TROJAN_GATEWAY_PROBE_BINARY','.work/gateway-integration.test')).resolve())+':/probe:ro'
 result=subprocess.run(['docker','run','--rm','--network','container:'+gateway,'--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--tmpfs','/tmp','-v',binary,'-v',sock+':/run/caddy:ro','-v',state+':/state','-v',data+':/data:ro','-v',certs+':/certs:ro','--entrypoint','/probe',control_image(),'-test.run','^TestRealAccessLogs$','-test.v','-test.timeout','80s'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=95)
 report['test_output']=result.stdout
 if result.returncode:raise RuntimeError('实际访问日志测试未通过')
 logs=container_logs(gateway)
 if 'synthetic-access-secret-' in logs or '198.51.100.99' in logs:raise RuntimeError('运行错误日志泄露敏感夹具')
 report.update(passed=True,runtime_error_log_sanitized=True,actual_compiler_and_gateway=True)
except Exception as error:
 report['error']=str(error)
 if gateway:report['gateway_logs']=container_logs(gateway)[-4000:]
finally:
 if gateway:command(['docker','rm','-f',gateway])
 for volume in reversed(volumes):command(['docker','volume','rm',volume])
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
