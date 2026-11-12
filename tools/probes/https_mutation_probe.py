"""显式TLS、证书就绪、端口协议隔离和持久格式的定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root=Path(__file__).resolve().parents[2]
base=root/'.work/https-mutations'/uuid.uuid4().hex[:10]
cases=[
 ('tls-policy','gateway/compile.go','if securePorts[port] && port != 443 {','if false && securePorts[port] && port != 443 {','gateway','TestCustomHTTPSRequiresAuthorizedReadyCertificate','custom HTTPS TLS policy missing'),
 ('certificate-ready','gateway/ingress.go','if s.Ingress != nil && (s.Ingress.AwaitCertificate ||','if s.Ingress != nil && (false ||','gateway','TestCustomHTTPSRequiresAuthorizedReadyCertificate','unsafe HTTPS rule accepted await-certificate'),
 ('mixed-protocol','routes/rule.go','exists && previous != secure','false && exists && previous != secure','gateway','TestCustomHTTPSRequiresAuthorizedReadyCertificate','unsafe HTTPS rule accepted mixed-port'),
 ('legacy-downgrade','storage/format.go','version = 4','version = 3','storage','TestHTTPSFormatProtectsPreparedAndRolledBackRules','HTTPS preparation did not reject legacy readers'),
 ('offline-downgrade','storage/format.go','if required >= 4 {','if false && required >= 4 {','storage','TestHTTPSFormatProtectsPreparedAndRolledBackRules','active HTTPS format downgrade accepted'),
]
report={}
for name,file,old,new,package,test,reason in cases:
 directory=base/name
 shutil.copytree(root/'internal',directory/'internal')
 for module in ['go.mod','go.sum']:shutil.copyfile(root/module,directory/module)
 path=directory/'internal'/file;source=path.read_text(encoding='utf-8')
 assert source.count(old)==1,(name,source.count(old))
 path.write_text(source.replace(old,new),encoding='utf-8')
 result=subprocess.run(['go','test','-C',str(directory),'./internal/'+package,'-run','^'+test+'$','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
 report[name]={'passed':True,'expected_failure':reason}
print(json.dumps({'passed':True,'mutations':report},indent=2))
