"""独立副本定向破坏订阅保护；必须命中特定失败，不能用任意红灯充数。"""
import json,shutil,subprocess,uuid
from pathlib import Path
root=Path(__file__).resolve().parents[2];base=root/'.work/subscription-mutations'/uuid.uuid4().hex[:10]
sql='SELECT count(*) FROM tokens WHERE digest=? AND owner=? AND revoked=0 AND expires>?'
cases=[
 ('revoked','subscription/store.go',sql,sql.replace(' AND revoked=0',''),'subscription','TestTokenPersistenceRevocationExpiryAndOwnerIsolation','revoked token accepted',False),
 ('expiry-boundary','subscription/store.go',sql,sql.replace('expires>?','expires>=?'),'subscription','TestTokenPersistenceRevocationExpiryAndOwnerIsolation','expired token accepted',False),
 ('owner-generation','subscription/store.go',sql,sql.replace('owner=?',"(?<>'' OR owner='')"),'subscription','TestTokenPersistenceRevocationExpiryAndOwnerIsolation','credential generation bypass',False),
 ('recent-mfa','api/subscription.go','if !s.Auth.Recent(bearer(r)) {','if false && !s.Auth.Recent(bearer(r)) {','api','TestSubscriptionHTTPAuthorizationAndScope','creation missing recent MFA accepted',False),
 ('post-export-revoke','subscription/service.go','if err = s.store.Validate(ctx, owner, token); err != nil {\n\t\treturn nil, err\n\t}','if false {\n\t\treturn nil, ErrDenied\n\t}','subscription','TestFetchRechecksRevocationAfterExport','revoked-during-export subscription leaked profile',True),
 ('direct-update','vpn/subscription.go','direct := "DOMAIN," + host + ",DIRECT"','direct := "DOMAIN," + host + ",PROXY"','vpn','TestSubscriptionDirectPrecedesCatchAllAndPreservesNode','subscription direct route corrupted config',False),
]
report={}
for name,file,old,new,package,test,reason,last in cases:
 directory=base/name;shutil.copytree(root/'internal',directory/'internal')
 for module in ('go.mod','go.sum'):shutil.copyfile(root/module,directory/module)
 path=directory/'internal'/file;source=path.read_text(encoding='utf-8');count=source.count(old)
 assert count==(2 if last else 1),(name,count)
 if last:
  at=source.rfind(old);source=source[:at]+new+source[at+len(old):]
 else:source=source.replace(old,new)
 path.write_text(source,encoding='utf-8')
 result=subprocess.run(['go','test','-C',str(directory),'./internal/'+package,'-run','^'+test+'$','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
 assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
 report[name]={'passed':True,'expected_failure':reason}
print(json.dumps({'passed':True,'mutations':report},indent=2))
