"""共享入口关键边界的独立副本定向破坏，必须命中指定断言。"""
import json,shutil,subprocess,uuid
from pathlib import Path
root=Path(__file__).resolve().parents[2];base=root/'.work/shared443-mutations'/uuid.uuid4().hex[:10]
cases=[
 ('format7','storage/format.go','version = 7','version = 6','storage','TestShared443FormatPreparationAndRollback','shared format computation fell below 7'),
 ('public-port','vpn/trojan.go','"port": publicPort','"port": s.Port','vpn','TestPublic443ExportDoesNotChangeEngine','public shared port ignored'),
 ('transition','gateway/transition.go','if err := configureSharedTrojan(current, oldServers); err != nil {','if false {','gateway','TestSharedTrojanTLSAndTransitionBoundaries','shared transition double TLS or lost current entry'),
 ('double-tls','gateway/shared_trojan.go','delete(server, "tls_connection_policies")','// disabled delete','gateway','TestSharedTrojanTLSAndTransitionBoundaries','shared TLS terminated twice or listener missing'),
]
report={}
for name,file,old,new,package,test,reason in cases:
 target=base/name;shutil.copytree(root/'internal',target/'internal')
 for module in ('go.mod','go.sum'):shutil.copyfile(root/module,target/module)
 p=target/'internal'/file;s=p.read_text(encoding='utf-8');assert s.count(old)==1,(name,s.count(old));p.write_text(s.replace(old,new),encoding='utf-8')
 r=subprocess.run(['go','test','-C',str(target),'./internal/'+package,'-run','^'+test+'$','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert r.returncode!=0 and reason in r.stdout,(name,r.returncode,r.stdout)
 report[name]={'expected_test_failure':reason}
for name,old,new,test,reason in [
 ('sni','states[len(states)-1].ServerName != m.SNI','false','TestExactSNIOnly','business SNI classified as Trojan'),
 ('short-http','for _, b := range data[:min(len(data), 56)] {','if len(data)<58{return false,layer4.ErrConsumedAllPrefetchedBytes}; for _, b := range data[:min(len(data), 56)] {','TestIncrementalPrefixAndShortHTTP','non-Trojan or short HTTP delayed'),
]:
 target=base/name;shutil.copytree(root/'engines/gateway',target)
 p=target/'trojanprefix/matcher.go';s=p.read_text(encoding='utf-8');assert s.count(old)==1;p.write_text(s.replace(old,new),encoding='utf-8')
 r=subprocess.run(['go','test','-C',str(target),'./trojanprefix','-run','^'+test+'$','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert r.returncode!=0 and reason in r.stdout,(name,r.returncode,r.stdout)
 report[name]={'expected_test_failure':reason}
print(json.dumps({'passed':True,'mutations':report},indent=2))
