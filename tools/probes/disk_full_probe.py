"""仅在一次性Linux容器8MiB tmpfs上执行真实ENOSPC与恢复验收。"""
import json
import os
from pathlib import Path
import subprocess
import uuid
from images import control_image

name='trojan-disk-full-'+uuid.uuid4().hex[:10]
binary=str(Path(os.environ.get('TROJAN_STORAGE_PROBE_BINARY','.work/storage-integration.test')).resolve())+':/probe:ro'
args=['docker','run','--name',name,'--network','none','--user','10001:10001','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--cpus','1','--tmpfs','/probe-data:rw,size=8m,uid=10001,gid=10001,mode=0700','--tmpfs','/tmp:rw,size=2m','-v',binary,'-e','TROJAN_DISK_FULL_TEST=1','--entrypoint','/probe',control_image(),'-test.run','^TestRealJournalDiskFullRecovery$','-test.v','-test.timeout','45s']
report={'passed':False,'scope':'disposable local Docker tmpfs only; no production server changes'}
try:
 result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=60)
 report.update({'exit_code':result.returncode,'output':result.stdout})
 details=json.loads(subprocess.check_output(['docker','inspect',name],text=True))[0]
 report['oom_killed']=details['State']['OOMKilled']
 report['passed']=result.returncode==0 and not report['oom_killed'] and 'TestRealJournalDiskFullRecovery/prepare' in result.stdout and 'TestRealJournalDiskFullRecovery/commit' in result.stdout and result.stdout.count('real ENOSPC after')==2
except Exception as error:report['error']=str(error)[:300]
finally:
 cleanup=subprocess.run(['docker','rm','-f',name],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15)
 report['disposable_container_removed']=cleanup.returncode==0
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] and report['disposable_container_removed'] else 1)
