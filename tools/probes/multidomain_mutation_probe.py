"""多域名的注册、证书就绪、后台证书、兼容格式及实际Host隔离指定破坏。"""
import json,os,shutil,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2];target=root/'.work/multidomain-mutations';report={}
cases=[
 ('registered-host','gateway/hosts.go','return ok','return ok || true','gateway','TestHostIsolationAndPendingCertificate','unregistered HTTPS host accepted'),
 ('unready-business','gateway/compile.go','ok && !ingressReady(host.Ingress)','false && ok && !ingressReady(host.Ingress)','gateway','TestHostIsolationAndPendingCertificate','unready host reached business upstream'),
 ('admin-certificate','site/planner.go','err == nil && site.AdminDomain != ""','false && err == nil && site.AdminDomain != ""','site','TestAdminDomainNeedsOwnCertificateAndPreservesVPN','primary certificate authorized administrator subdomain'),
 ('format6','storage/format.go','version = 6','version = 5','storage','TestDomainFormatPreparedRollbackAndSafeDowngrade','prepared domains not format protected'),
]
def prepare(name):
 directory=target/name;shutil.copytree(root/'internal',directory/'internal',dirs_exist_ok=True)
 for file in ['go.mod','go.sum']:shutil.copyfile(root/file,directory/file)
 return directory
for name,filename,old,new,package,test,reason in cases:
 directory=prepare(name);path=directory/'internal'/filename;source=path.read_text(encoding='utf-8');assert source.count(old)==1,(name,source.count(old));path.write_text(source.replace(old,new),encoding='utf-8')
 env=dict(os.environ)
 for key in ['GOOS','GOARCH','CGO_ENABLED']:env.pop(key,None)
 result=subprocess.run(['go','test','-C',str(directory),'./internal/'+package,'-run','^'+test+'$','-count=1'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert result.returncode and reason in result.stdout,(name,result.returncode,result.stdout);report[name]={'passed':True,'expected_failure':reason}
directory=prepare('actual-host-routing');path=directory/'internal/gateway/compile.go';source=path.read_text(encoding='utf-8');old='if r.Host != "" {';assert source.count(old)==1;path.write_text(source.replace(old,'if false && r.Host != "" {'),encoding='utf-8')
binary=directory/'gateway-mutated.test';env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',PYTHONIOENCODING='utf-8')
result=subprocess.run(['go','test','-C',str(directory),'-c','-tags','integration','-o',str(binary),'./internal/gateway'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=120)
if result.returncode:raise RuntimeError(result.stdout[-2000:])
env['TROJAN_GATEWAY_PROBE_BINARY']=str(binary)
negative=subprocess.run([sys.executable,str(root/'tools/probes/multidomain_probe.py')],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=110)
value=json.loads(negative.stdout);reason='hostname isolation changed';assert negative.returncode==1 and value.get('passed') is False and reason in value.get('test',{}).get('output',''),value
report['actual-host-routing']={'passed':True,'expected_failure':reason,'actual_gateway':True}
print(json.dumps({'passed':True,'mutations':report},ensure_ascii=False,indent=2))
