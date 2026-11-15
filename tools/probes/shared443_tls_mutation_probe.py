"""真正去掉回环TLS校验后，必须因错误后端SNI仍读取哨兵而失败。"""
import json,os,subprocess,sys
from pathlib import Path
env=dict(os.environ,TROJAN_SHARED_TLS_MUTATION='1',PYTHONIOENCODING='utf-8')
r=subprocess.run([sys.executable,str(Path(__file__).with_name('shared443_probe.py'))],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding='utf-8',timeout=150)
report=json.loads(r.stdout)
expected='backend wrong SNI still served target'
assert r.returncode!=0 and not report['passed'] and expected in report['checks'].get('shared_web',{}).get('output',''),(r.returncode,report,r.stderr)
print(json.dumps({'passed':True,'expected_test_failure':expected,'scope':'actual gateway TLS verification disabled in disposable config only'},indent=2))
