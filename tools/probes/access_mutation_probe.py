"""网站访问：独立查询TTL、物理清理、真实来源和近期MFA的定向破坏。"""
import json,os,shutil,subprocess,sys
from pathlib import Path

root=Path(__file__).resolve().parents[2]
target=root/'.work/access-mutations'
cases=[
 ('trusted-query-ttl','webaccess/query.go','where := " WHERE (trusted=0 OR at>?)"','where := " WHERE (1 OR at>?)"','./internal/webaccess','TestTrustedQueryTTLIndependentOfPruning','trusted query exposed expired history'),
 ('physical-expiry','webaccess/store.go','DELETE FROM requests WHERE at<=? OR (','DELETE FROM requests WHERE 0 AND (at<=? OR (','./internal/webaccess','TestRetentionCurrentWhitelistAndExactBoundaries','到期记录未物理删除'),
 ('actual-connection-ip','webaccess/parse.go','json:"remote_ip"','json:"client_ip"','./internal/webaccess','TestParserPrivacyAndHostileInput','隐私字段或真实来源错误'),
 ('recent-mfa','api/access.go','if !s.Auth.Recent(bearer(r)) {','if false && !s.Auth.Recent(bearer(r)) {','./internal/api','TestWebAccessAuthenticationMFAAndValidation','访问白名单绕过近期MFA'),
 ('full-store-cleanup','webaccess/service.go','if now.Sub(lastPrune) >= time.Minute {','if false && now.Sub(lastPrune) >= time.Minute {','./internal/webaccess','TestFullCollectorPrunesBeforeRetry','满库阻止到期清理与采集恢复'),
]
report={}
for name,filename,old,new,package,test,reason in cases:
 directory=target/name
 shutil.copytree(root/'internal',directory/'internal',dirs_exist_ok=True)
 for module in ('go.mod','go.sum'):shutil.copyfile(root/module,directory/module)
 path=directory/'internal'/filename;source=path.read_text(encoding='utf-8')
 assert source.count(old)==1,(name,source.count(old))
 source=source.replace(old,new)
 if name=='physical-expiry':
  source=source.replace('+" AND at<=?)", params...', '+" AND at<=?))", params...')
 path.write_text(source,encoding='utf-8')
 environment=dict(os.environ);environment.pop('GOOS',None);environment.pop('GOARCH',None);environment.pop('CGO_ENABLED',None)
 result=subprocess.run(['go','test','-C',str(directory),package,'-run','^'+test+'$','-count=1'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
 report[name]={'passed':True,'expected_failure':reason}

# 实际网关反向测试：删去URI查询过滤，必须在原始文件中捕获秘密，不能依赖入库补救。
directory=target/'raw-query';shutil.copytree(root/'internal',directory/'internal',dirs_exist_ok=True)
for module in ('go.mod','go.sum'):shutil.copyfile(root/module,directory/module)
path=directory/'internal/gateway/access_log.go';source=path.read_text(encoding='utf-8');old=r'|\?.*$'
assert source.count(old)==1,'query encoder guard changed'
path.write_text(source.replace(old,''),encoding='utf-8')
binary=directory/'gateway-mutated.test'
environment=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',PYTHONIOENCODING='utf-8')
build=subprocess.run(['go','test','-C',str(directory),'-c','-tags','integration','-o',str(binary),'./internal/gateway'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=120)
if build.returncode:raise RuntimeError(build.stdout[-2000:])
environment['TROJAN_GATEWAY_PROBE_BINARY']=str(binary)
negative=subprocess.run([sys.executable,str(root/'tools/probes/access_logs_probe.py')],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=110)
result=json.loads(negative.stdout);reason='落盘前隐私过滤失效'
assert negative.returncode==1 and result.get('passed') is False and reason in result.get('test_output',''),result
report['raw-query-before-disk']={'passed':True,'expected_failure':reason,'real_gateway':True}
print(json.dumps({'passed':True,'mutations':report},ensure_ascii=False,indent=2))
