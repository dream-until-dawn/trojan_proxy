"""验证真实镜像拒绝未绑定账户启动，失败必须匹配指定原因。"""
import json
from pathlib import Path
import subprocess

config=str(Path('deploy/admin.proxy.example.json').resolve())+':/etc/trojan-proxy/proxy.json:ro'
base=['docker','run','--rm','--network','none','--read-only','--cap-drop','ALL',
      '--security-opt','no-new-privileges','--tmpfs','/data:uid=10001,gid=10001,mode=0700','-v',config]
checks={}
for name,args,expected in [
    ('uninitialized_account_refuses_start',['trojan-control:m4'],'管理员尚未初始化'),
    ('noninteractive_enrollment_refused',['--entrypoint','proxyctl','trojan-control:m4','admin-init','--config','/etc/trojan-proxy/proxy.json'],'请在交互终端运行管理员初始化')]:
    result=subprocess.run(base+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding='utf-8',timeout=20)
    assert result.returncode!=0 and expected in result.stderr,(name,result.returncode,result.stderr)
    checks[name]='PASS'
print(json.dumps({'checks':checks,'passed':True},ensure_ascii=False,indent=2))
