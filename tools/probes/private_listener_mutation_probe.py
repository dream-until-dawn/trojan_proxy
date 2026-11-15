"""回环收口和公开443观察的独立定向破坏，必须命中指定安全断言。"""
import json,shutil,subprocess,sys,uuid
from pathlib import Path
root=Path(__file__).resolve().parents[2];base=root/'.work/private-listener-mutations'/uuid.uuid4().hex[:10]
cases=[
 ('old-page','api/settings.go','if current.Site.VPNLoopbackOnly {','if false && current.Site.VPNLoopbackOnly {','api','TestOldPageCannotReopenPrivateListener','old page silently reopened private listener'),
 ('listen','vpn/trojan.go','listen = "127.0.0.1"','listen = "::"','vpn','TestPrivateListenerVersionAndPublicExport','private listener compiled as public'),
 ('version','vpn/profile.go','(p.Version != 1 || p.LoopbackOnly) && (p.Version != 2 || !p.LoopbackOnly)','false','vpn','TestPrivateListenerVersionAndPublicExport','private mode accepted ambiguous profile version'),
 ('export','vpn/trojan.go','if s.LoopbackOnly && publicPort != 443 {','if false {','vpn','TestPrivateListenerVersionAndPublicExport','private backend exported as public'),
 ('shared-required','settings/model.go','if d.Site.VPNLoopbackOnly && !d.Site.SharedTrojan443 {','if false {','settings','TestPrivateListenerRequiresShared443','private listener accepted without shared ingress'),
 ('format8','storage/format.go','version = 8','version = 7','storage','TestPrivateListenerFormatAndSafeRollback','private format computation fell below 8'),
 ('no-web-reload','gateway/transition.go','if reflect.DeepEqual(current, candidate) {','if false {','site','TestPrivateListenerPlanPreservesGatewayAndCredential','private candidate reloaded gateway or VPN'),
]
report={}
for name,file,old,new,package,test,reason in cases:
 target=base/name;shutil.copytree(root/'internal',target/'internal')
 for module in ('go.mod','go.sum'):shutil.copyfile(root/module,target/module)
 p=target/'internal'/file;s=p.read_text(encoding='utf-8');assert s.count(old)==1,(name,s.count(old));p.write_text(s.replace(old,new),encoding='utf-8')
 r=subprocess.run(['go','test','-C',str(target),'./internal/'+package,'-run','^'+test+'$','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert r.returncode!=0 and reason in r.stdout,(name,r.returncode,r.stdout)
 report[name]={'expected_test_failure':reason}
target=base/'public-probe';shutil.copytree(root/'tools/stability',target)
p=target/'checks.py';s=p.read_text(encoding='utf-8');old="if expected_port is not None and (type(result.get('port')) is not int or result['port']!=expected_port):"
assert s.count(old)==1;p.write_text(s.replace(old,'if False:'),encoding='utf-8')
r=subprocess.run([sys.executable,'-m','unittest','test_vpn_checks.PrivateVPNTests.test_deep_probe_cannot_substitute_private_backend'],cwd=target,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=20)
assert r.returncode!=0 and 'CheckFailure not raised' in r.stdout and 'test_deep_probe_cannot_substitute_private_backend' in r.stdout,r.stdout
report['public-probe']={'expected_test_failure':'private backend cannot replace public443 proof'}
print(json.dumps({'passed':True,'mutations':report},indent=2))
