"""在忽略目录复制源码做定向破坏；必须因指定安全断言失败。"""
import json
from pathlib import Path
import shutil
import subprocess

repo=Path(__file__).resolve().parents[2]
target=repo/'.work/auth-mutations'
target.mkdir(parents=True,exist_ok=True)
cases=[
    ('authentication','server.go','if !s.Auth.Validate(bearer(r)) {','if false {','未认证读取未拒绝: 200'),
    ('origin','server.go','if strings.HasPrefix(r.URL.Path, "/api/") && !s.Origins[r.Header.Get("Origin")] {','if false {','跨来源未拒绝:'),
    ('recent_mfa','routes.go','if !s.Auth.Recent(bearer(r)) {','if false {','近期双因素保护未拒绝: 200')
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
    source=path.read_text(encoding='utf-8');assert source.count(old)==1,name
    path.write_text(source.replace(old,new),encoding='utf-8')
    result=subprocess.run(['go','test','-C',str(directory),'./internal/api','-run','TestAPIOriginAuthenticationAndLogout|TestRouteAPIRecentMFAAndRevisions','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
    assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
    results[name]={'expected_test_failure':True,'reason':reason}
print(json.dumps({'mutations':results,'passed':True},ensure_ascii=False,indent=2))
