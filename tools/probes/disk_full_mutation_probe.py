"""故意忽略准备修订写盘失败，必须命中引擎不得提前应用的断言。"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

root=Path(__file__).resolve().parents[2]
target=root/'.work/disk-full-mutation'/uuid.uuid4().hex[:10]
shutil.copytree(root/'internal',target/'internal')
for module in ('go.mod','go.sum'):shutil.copyfile(root/module,target/module)
path=target/'internal/runtime/revision.go';source=path.read_text(encoding='utf-8')
old='if err = c.store.Save(ctx, j); err != nil {\n\t\treturn err\n\t}'
assert source.count(old)==1,'prepare error guard location changed'
path.write_text(source.replace(old,'if err = c.store.Save(ctx, j); false {\n\t\treturn err\n\t}'),encoding='utf-8')
binary=target/'storage-mutated.test'
environment=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',PYTHONIOENCODING='utf-8')
build=subprocess.run(['go','test','-C',str(target),'-c','-tags','integration','-o',str(binary),'./internal/storage'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=120)
if build.returncode:raise RuntimeError(build.stdout[-2000:])
environment['TROJAN_STORAGE_PROBE_BINARY']=str(binary)
negative=subprocess.run([sys.executable,str(root/'tools/probes/disk_full_probe.py')],env=environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
result=json.loads(negative.stdout)
reason='failed prepare still applied engine configuration'
assert negative.returncode==1 and result.get('passed') is False and reason in result.get('output','') and result.get('oom_killed') is False and result.get('disposable_container_removed') is True,result
print(json.dumps({'passed':True,'expected_failure':reason,'actual_storage_fault':'real ENOSPC and SQLite FULL','disposable_container_removed':True},indent=2))
