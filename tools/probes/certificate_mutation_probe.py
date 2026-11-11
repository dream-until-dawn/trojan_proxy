"""定向删除证书保护，只有预期安全断言失败才算证明测试有效。"""
import json
from pathlib import Path
import shutil
import subprocess

repo=Path(__file__).resolve().parents[2]
target=repo/'.work/certificate-mutations'
cases=[
    ('domain','DNSName: domain','DNSName: ""','错误域名通过'),
    ('validity','CurrentTime: now','CurrentTime: leaf.NotBefore.Add(time.Second)','过期证书通过'),
]
results={}
for name,old,new,reason in cases:
    directory=target/name
    for source in (repo/'internal').rglob('*'):
        if source.is_file():
            dest=directory/'internal'/source.relative_to(repo/'internal')
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(source,dest)
    for module in ('go.mod','go.sum'):shutil.copyfile(repo/module,directory/module)
    path=directory/'internal/certificates/pair.go'
    source=path.read_text(encoding='utf-8')
    assert source.count(old)==1,name
    path.write_text(source.replace(old,new),encoding='utf-8')
    result=subprocess.run(['go','test','-C',str(directory),'./internal/certificates','-run','^TestPairValidationAndImmutablePublish$','-count=1'],
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
    assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
    results[name]={'expected_test_failure':True,'reason':reason}
print(json.dumps({'mutations':results,'passed':True},ensure_ascii=False,indent=2))
