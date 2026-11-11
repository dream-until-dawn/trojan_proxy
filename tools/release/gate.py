"""部署前门槛：绑定离线包、实际二进制、三模块检查与真实正反向探针。"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import uuid

ROOT=Path(__file__).resolve().parents[2]
ARCHIVE=ROOT/'.work/m6-images.tar.gz'
OUTPUT=ROOT/'.work/m6-gate.json'
LOGS=ROOT/'.work/release-gate'
BINARIES={
    'trojan-control:m6':['usr/local/bin/control','usr/local/bin/proxyctl'],
    'trojan-runner:dev':['usr/local/bin/vpnrunner','usr/local/bin/trojan-engine'],
    'trojan-gateway:dev':['usr/bin/caddy'],
}
SCANNER=ROOT/('.work/bin/govulncheck.exe' if os.name=='nt' else '.work/bin/govulncheck')
report={'passed':False,'checks':{},'images':{},'binaries':{},'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
LOGS.mkdir(parents=True,exist_ok=True)
environment=dict(os.environ,PYTHONIOENCODING='utf-8',TROJAN_EGRESS_MUTATION='0',TROJAN_GATEWAY_IMAGE='trojan-gateway:dev')
for setting in ('GOOS','GOARCH','CGO_ENABLED'):environment.pop(setting,None)

def command(args,cwd=ROOT,env=None,timeout=180,log=None):
    result=subprocess.run([str(arg) for arg in args],cwd=cwd,env=env or environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=timeout)
    if log:(LOGS/log).write_text(result.stdout,encoding='utf-8')
    if result.returncode:raise RuntimeError('门槛失败: '+str(args[:3])+'；见 '+str(log or result.stdout[-800:]))
    return result.stdout.strip()

def file_hash(path):
    digest=hashlib.sha256()
    with open(path,'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()

def progress(name):
    print('验证:',name,flush=True)

try:
    if command(['git','status','--porcelain']):raise RuntimeError('先提交源码，再生成绑定确切提交的部署门槛')
    report['commit']=command(['git','rev-parse','HEAD'])
    report['archive_sha256']=file_hash(ARCHIVE)
    report['scanner']=command([SCANNER,'-version'])
    progress('从离线包提取实际Go二进制，逐个扫描')
    with tarfile.open(ARCHIVE) as outer:
        manifest=json.load(outer.extractfile('manifest.json'))
        for tag,paths in BINARIES.items():
            entries=[entry for entry in manifest if tag in entry.get('RepoTags',[])]
            if len(entries)!=1:raise RuntimeError('离线包缺少唯一镜像: '+tag)
            entry=entries[0]
            report['images'][tag]='sha256:'+hashlib.sha256(outer.extractfile(entry['Config']).read()).hexdigest()
            selected={}
            for layer in entry['Layers']:
                with tarfile.open(fileobj=outer.extractfile(layer),mode='r:*') as files:
                    for member in files:
                        name=member.name.lstrip('./')
                        if name not in paths:continue
                        if not member.isfile() or member.size>128*1024*1024:raise RuntimeError('引擎文件类型或大小无效')
                        selected[name]=files.extractfile(member).read()
            if set(selected)!=set(paths):raise RuntimeError('镜像缺少预期可执行文件: '+tag)
            container=None
            try:
                container=command(['docker','create','--network','none','--name','trojan-gate-'+uuid.uuid4().hex[:10],tag])
                for path,body in selected.items():
                    name=tag.replace(':','-')+'-'+Path(path).name
                    packaged=LOGS/(name+'.bin');packaged.write_bytes(body)
                    local=LOGS/(name+'.local')
                    command(['docker','cp',container+':/'+path,local])
                    if file_hash(local)!=file_hash(packaged):raise RuntimeError('探针本地镜像与待部署离线包不同: '+name)
                    command([SCANNER,'-mode=binary',packaged],log=name+'-binary.log')
                    report['binaries'][name]={'sha256':file_hash(packaged),'bytes':len(body),'scan':'passed'}
            finally:
                if container:command(['docker','rm',container])
    report['checks']['packaged_binaries_and_local_images']='passed'
    progress('根模块与两个独立引擎模块测试、静态检查')
    command([sys.executable,'tools/validate.py'],log='modules.log')
    report['checks']['three_modules_test_vet']='passed'
    progress('Linux关键并发路径race检查')
    command(['docker','build','-f','deploy/Dockerfile.tests','-t','trojan-tests:release','.'],timeout=240,log='linux-race.log')
    report['checks']['linux_race']='passed'
    linux=dict(environment,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0')
    for name,module in [('control',ROOT),('trojan',ROOT/'engines/trojan'),('gateway',ROOT/'engines/gateway')]:
        progress('Linux源码漏洞扫描 '+name)
        command([SCANNER,'./...'],cwd=module,env=linux,log=name+'-source.log')
        report['checks'][name+'_linux_source_scan']='passed'
    for name,package in [('gateway','gateway'),('certificates','certificates'),('vpn','vpn'),('runner','vpnrunner')]:
        command(['go','test','-c','-tags','integration','-o','.work/'+name+'-integration.test','./internal/'+package],env=linux,log=name+'-build.log')
    probes=['gateway_lifecycle','acme_lifecycle','certificate_cache','vpn_egress','runner_lifecycle','auth_mutation','certificate_mutation','bootstrap_mutation','welcome_mutation']
    for name in probes:
        progress('真实探针 '+name)
        output=command([sys.executable,'tools/probes/'+name+'_probe.py'],log=name+'.json')
        if json.loads(output).get('passed') is not True:raise RuntimeError('探针没有明确通过: '+name)
        report['checks'][name]='passed'
    progress('真实VPN目的地址定向破坏')
    output=command([sys.executable,'tools/probes/vpn_egress_probe.py'],env=dict(environment,TROJAN_EGRESS_MUTATION='1'),log='vpn-egress-mutation.json')
    result=json.loads(output)
    if result.get('expected_mutation_failure')!='目的地址保护失效 127.0.0.1 public-sentinel':raise RuntimeError('定向破坏未触发指定断言')
    report['checks']['vpn_egress_mutation']='passed'
    if command(['git','status','--porcelain']):raise RuntimeError('门槛执行期间源码发生变化')
    report['passed']=True
except Exception as error:
    report['error']=str(error)
finally:
    OUTPUT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
