"""真实Caddy+独立SQLite+真实认证的订阅流程；只使用一次性虚构凭据。"""
import json,os,subprocess,uuid
from pathlib import Path
from images import control_image,gateway_image,openssl_image,container_logs
from gateway_probe import command

prefix='trojan-subscription-'+uuid.uuid4().hex[:10];volumes=[];gateway=None;report={'passed':False,'production_used':False}
try:
 for kind in ('socket','certs','state','data'):volumes.append(command(['docker','volume','create',prefix+'-'+kind]))
 sock,certs,state,data=volumes
 command(['docker','run','--rm','--network','none','-v',sock+':/socket','-v',state+':/state','-v',data+':/data','alpine:3.22','sh','-c','chown 0:10001 /socket && chmod 0770 /socket && chown 10001:10001 /state /data && chmod 0700 /state /data'])
 command(['docker','run','--rm','--network','none','-v',certs+':/certs',openssl_image(),'req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout','/certs/private.key','-out','/certs/fullchain.cer','-subj','/CN=localhost.test','-addext','subjectAltName=DNS:localhost.test'])
 command(['docker','run','--rm','--network','none','-v',certs+':/certs','alpine:3.22','sh','-c','chown 0:10001 /certs/* && chmod 0640 /certs/*'])
 gateway=command(['docker','run','-d','--name',prefix+'-gateway','--user','0:10001','--read-only','--cap-drop','ALL','--cap-add','SETUID','--cap-add','SETGID','--cap-add','SETPCAP','--cap-add','NET_BIND_SERVICE','--security-opt','no-new-privileges','--memory','192m','-v',sock+':/run/caddy','-v',certs+':/certs:ro','-v',certs+':/certificates/test:ro','-v',data+':/data','--tmpfs','/config:uid=10001,gid=10001,mode=0700','-e','CADDY_ADMIN=unix//run/caddy/admin.sock|0660',gateway_image(),'caddy','run'])
 binary=str(Path(os.environ.get('TROJAN_SUBSCRIPTION_PROBE_BINARY','.work/api-integration.test')).resolve())+':/probe:ro'
 result=subprocess.run(['docker','run','--rm','--network','container:'+gateway,'--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--tmpfs','/tmp','-v',binary,'-v',sock+':/run/caddy:ro','-v',state+':/state','-v',data+':/data:ro','-v',certs+':/certs:ro','--entrypoint','/probe',control_image(),'-test.run','^TestRealSubscriptionIngress$','-test.v','-test.timeout','30s'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=45)
 report['test_output']=result.stdout
 if result.returncode:raise RuntimeError('真实HTTPS订阅流程未通过')
 markers=json.loads(command(['docker','run','--rm','--network','none','-v',state+':/state:ro','alpine:3.22','cat','/state/subscription-markers.json']))
 logs=container_logs(gateway)
 if any(value in logs for value in markers):raise RuntimeError('订阅凭据进入网关运行日志')
 client='metacubex/mihomo@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c'
 parsed=subprocess.run(['docker','run','--rm','--network','none','--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','256m','--tmpfs','/tmp:uid=10001,gid=10001,mode=0700','-v',state+':/state:ro',client,'-d','/tmp','-t','-f','/state/subscription-profile.yaml'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=30)
 report['mihomo_check_output']=parsed.stdout
 if parsed.returncode:raise RuntimeError('Mihomo配置解析失败，退出码'+str(parsed.returncode))
 report.update(passed=True,actual_gateway=True,log_secrets_absent=True,mihomo_downloaded_profile_parsed=True,limitations=['不替代Clash Verge和Clash Mi真实远程订阅导入及更新验收。'])
except Exception as error:
 report['error']=str(error)
 if gateway:
  Path('.work/subscription-gateway-error.log').write_text(container_logs(gateway),encoding='utf-8')
finally:
 if gateway:command(['docker','rm','-f',gateway])
 for volume in reversed(volumes):command(['docker','volume','rm',volume])
print(json.dumps(report,ensure_ascii=False,indent=2));raise SystemExit(0 if report['passed'] else 1)
