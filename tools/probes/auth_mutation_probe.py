"""在忽略目录复制源码做定向破坏；必须因指定安全断言失败。"""
import json
from pathlib import Path
import shutil
import subprocess

repo=Path(__file__).resolve().parents[2]
target=repo/'.work/auth-mutations'
target.mkdir(parents=True,exist_ok=True)
cases=[
    ('authentication','server.go','if !valid {','if !valid && false {','未认证读取未拒绝: 200'),
    ('origin','server.go','if strings.HasPrefix(r.URL.Path, "/api/") && !origins[r.Header.Get("Origin")] {','if false {','跨来源未拒绝:'),
    ('recent_mfa','routes.go','if !s.Auth.Recent(bearer(r)) {','if false {','近期双因素保护未拒绝: 200'),
    ('vpn_recent_mfa','vpn.go','if !s.Auth.Recent(bearer(r)) {','if false {','VPN近期MFA未拒绝 /api/vpn/apply: 200'),
    ('vpn_export_mfa','vpn.go','if !s.Auth.Recent(bearer(r)) {','if false {','VPN近期MFA未拒绝 /api/vpn/export: 200')
]
results={}
for name,filename,old,new,reason in cases:
    directory=target/name
    # 不删除任何现有目录；重复执行通过逐文件覆盖本脚本自有副本。
    (directory/'internal').mkdir(parents=True,exist_ok=True)
    for source in (repo/'internal').rglob('*'):
        if source.is_file():
            dest=directory/'internal'/source.relative_to(repo/'internal')
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,dest)
    for module in ('go.mod','go.sum'):shutil.copyfile(repo/module,directory/module)
    path=directory/'internal/api'/filename
    source=path.read_text(encoding='utf-8')
    if name in ('vpn_recent_mfa','vpn_export_mfa'):
        assert source.count(old)==2,name
        position=source.index(old) if name=='vpn_recent_mfa' else source.rindex(old)
        source=source[:position]+source[position:].replace(old,new,1)
    else:
        assert source.count(old)==1,name
        source=source.replace(old,new)
    path.write_text(source,encoding='utf-8')
    result=subprocess.run(['go','test','-C',str(directory),'./internal/api','-run','TestAPIOriginAuthenticationAndLogout|TestRouteAPIRecentMFAAndRevisions|TestVPNAPIRequiresAuthOriginAndRecentMFA','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
    assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
    results[name]={'expected_test_failure':True,'reason':reason}
print(json.dumps({'mutations':results,'passed':True},ensure_ascii=False,indent=2))
