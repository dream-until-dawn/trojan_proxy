"""部署前门槛：绑定离线包、实际二进制、三模块检查与真实正反向探针。"""
import argparse
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
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--archive',type=Path,default=ROOT/'.work/m6-images.tar.gz')
parser.add_argument('--output',type=Path,default=ROOT/'.work/m6-gate.json')
args=parser.parse_args()
ARCHIVE=args.archive.resolve()
OUTPUT=args.output.resolve()
LOGS=ROOT/'.work/release-gate'
BINARIES={
    'trojan-control:m6':['usr/local/bin/control','usr/local/bin/proxyctl'],
    'trojan-runner:dev':['usr/local/bin/vpnrunner','usr/local/bin/trojan-engine'],
    'trojan-gateway:dev':['usr/bin/caddy','usr/local/bin/gateway-entry'],
}
SCANNER=ROOT/('.work/bin/govulncheck.exe' if os.name=='nt' else '.work/bin/govulncheck')
report={'passed':False,'checks':{},'images':{},'binaries':{},'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
LOGS.mkdir(parents=True,exist_ok=True)
environment=dict(os.environ,PYTHONIOENCODING='utf-8',TROJAN_EGRESS_MUTATION='0',TROJAN_GATEWAY_IMAGE='trojan-gateway:dev',TROJAN_CONTROL_IMAGE='trojan-control:m6',TROJAN_RUNNER_IMAGE='trojan-runner:dev')
for setting in ('GOOS','GOARCH','CGO_ENABLED'):environment.pop(setting,None)

def command(args,cwd=ROOT,env=None,timeout=180,log=None):
    result=subprocess.run([str(arg) for arg in args],cwd=cwd,env=env or environment,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=timeout)
    if log:(LOGS/log).write_text(result.stdout,encoding='utf-8')
    if result.returncode:raise RuntimeError('门槛失败: '+str(args[:3])+'；见 '+str(log or '')+'\n'+result.stdout[-4000:])
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
            config_body=outer.extractfile(entry['Config']).read()
            config=json.loads(config_body)
            if config.get('config',{}).get('Labels',{}).get('org.opencontainers.image.revision')!=report['commit']:
                raise RuntimeError('镜像缺少本次确切提交标签，请使用 --label org.opencontainers.image.revision=<HEAD> 重建: '+tag)
            report['images'][tag]='sha256:'+hashlib.sha256(config_body).hexdigest()
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
    command([sys.executable,'-m','unittest','discover','-s','tools/stability','-p','test_*.py'],log='stability-verdicts.log')
    report['checks']['stability_positive_negative_verdicts']='passed'
    progress('Linux关键并发路径race检查')
    command(['docker','build','-f','deploy/Dockerfile.tests','-t','trojan-tests:release','.'],timeout=240,log='linux-race.log')
    report['checks']['linux_race']='passed'
    linux=dict(environment,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0')
    for name,module in [('control',ROOT),('trojan',ROOT/'engines/trojan'),('gateway',ROOT/'engines/gateway')]:
        progress('Linux源码漏洞扫描 '+name)
        command([SCANNER,'./...'],cwd=module,env=linux,log=name+'-source.log')
        report['checks'][name+'_linux_source_scan']='passed'
    progress('显式准备固定探针夹具，不依赖开发机缓存或旧产品镜像')
    fixtures=['alpine:3.22','python:3.12-slim',
        'alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb',
        'ghcr.io/letsencrypt/pebble@sha256:0c81f05db371f436c97fb894bd6d2ab8fc9c8e2ce40f8bef8a8e15941bcd75ef',
        'metacubex/mihomo@sha256:9211361a3ed85305383288d38c05e85862d6d5a590c10007c37fc059cca82e9c']
    for fixture in fixtures:
        inspect=subprocess.run(['docker','image','inspect',fixture],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if inspect.returncode:command(['docker','pull',fixture],timeout=180,log='fixture-'+fixture.split('/')[0].replace(':','-')+'.log')
    report['checks']['explicit_probe_fixtures']='passed'
    for name,package in [('gateway','gateway'),('certificates','certificates'),('vpn','vpn'),('runner','vpnrunner'),('deployment','deployment')]:
        command(['go','test','-c','-tags','integration','-o','.work/'+name+'-integration.test','./internal/'+package],env=linux,log=name+'-build.log')
    probes=['gateway_lifecycle','keepalive_mutation','acme_lifecycle','certificate_cache','vpn_egress','runner_lifecycle','auth_mutation','certificate_mutation','bootstrap_mutation','welcome_mutation','settings_mutation','telemetry','telemetry_mutation','traffic_mutation','profile_mutation','settings_view_mutation','certificate_control_mutation','recovery_mutation','default_deployment']
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
    progress('持久证书缓存被可写tmpfs覆盖的定向破坏')
    negative=subprocess.run([sys.executable,'tools/probes/default_deployment_probe.py'],cwd=ROOT,env=dict(environment,TROJAN_GATEWAY_CACHE_MUTATION='1'),stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
    (LOGS/'cache-mount-mutation.json').write_text(negative.stdout,encoding='utf-8')
    result=json.loads(negative.stdout)
    if negative.returncode==0 or result.get('error')!='gateway cache mount is not persistent' or result.get('disposable_project_cleanup') is not True:raise RuntimeError('临时盘覆盖未命中持久性保护断言')
    report['checks']['gateway_cache_mount_mutation']='passed'
    if command(['git','status','--porcelain']):raise RuntimeError('门槛执行期间源码发生变化')
    report['passed']=True
except Exception as error:
    report['error']=str(error)
finally:
    OUTPUT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report['passed'] else 1)
