param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$KeyPath
)
$ErrorActionPreference='Stop'
$repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if((Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'deploy/compose.admin.yaml')) -notmatch 'image: trojan-control:m4\s') {throw '此历史探针只适用于M3到M4；当前源码请使用经过release gate的upgrade_vpn.ps1'}
$archive=Join-Path $repoRoot '.work/control-m4.tar.gz'
$hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
$tarPath=Join-Path $repoRoot '.work/control-m4.tar'
$imageId=@'
import sys,tarfile,json,hashlib
with tarfile.open(sys.argv[1]) as archive:
    manifest=json.load(archive.extractfile('manifest.json'))
    entry=next(e for e in manifest if 'trojan-control:m4' in e.get('RepoTags',[]))
    print('sha256:'+hashlib.sha256(archive.extractfile(entry['Config']).read()).hexdigest())
'@ | python - $tarPath
if ($LASTEXITCODE -ne 0) {throw '镜像摘要计算失败'}
$files=@{};$expected=@{}
foreach($name in @('compose.admin.yaml','Caddyfile.admin','admin.proxy.example.json')) {
    $files[$name]=(Get-Content -Raw -LiteralPath (Join-Path $repoRoot "deploy/$name")).Replace("`r`n","`n")
    $baseline=git -C $repoRoot show "91466a6:deploy/$name"
    if($LASTEXITCODE -ne 0){throw '旧部署基线不可读取'}
    $expected[$name]=($baseline -join "`n")+"`n"
}
$payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{files=$files;expected=$expected} | ConvertTo-Json -Depth 5 -Compress)))
$probeDir=Join-Path $env:TEMP ('trojan-upgrade-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $probeDir | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $probeDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if($LASTEXITCODE -ne 0){throw '密钥临时目录权限设置失败'}
$probeKey=Join-Path $probeDir 'identity.pem'
$remoteArchive='/tmp/trojan-m4-'+[guid]::NewGuid().ToString('N')+'.tar.gz'
try {
    Copy-Item -LiteralPath $KeyPath -Destination $probeKey
    scp -C -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes $archive "${Server}:$remoteArchive"
    if($LASTEXITCODE -ne 0){throw '升级镜像传输失败'}
    $script=@"
import os,json,base64,hashlib,subprocess,sqlite3,shutil,socket,time,datetime,urllib.request
root='/opt/trojan-proxy-refactor'
upload='$remoteArchive'
payload=json.loads(base64.b64decode('$payload').decode('utf-8'))
def run(args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=90)
    if result.returncode:raise RuntimeError(result.stderr)
    return result.stdout.strip()
def snapshot():
    ids=run(['docker','ps','-q']).split()
    result={}
    for c in json.loads(run(['docker','inspect']+ids)) if ids else []:
        if c['Config'].get('Labels',{}).get('com.docker.compose.project')!='trojan-refactor':result[c['Id']]=c['State']['StartedAt']
    return result
before=snapshot()
compose=['docker','compose','-p','trojan-refactor','-f',os.path.join(root,'compose.admin.yaml')]
old={};changed=False
try:
    if not os.path.isfile(os.path.join(root,'.managed-by-trojan-refactor')):raise RuntimeError('目标不是受管部署')
    with open(upload,'rb') as stream:
        if hashlib.sha256(stream.read()).hexdigest()!='$hash':raise RuntimeError('升级包摘要错误')
    for name,expected in payload['expected'].items():
        with open(os.path.join(root,name)) as stream:body=stream.read()
        if body.rstrip()!=expected.rstrip():raise RuntimeError('配置偏离已验证基线，拒绝覆盖: '+name)
        old[name]=body
    # 验证占用的8007/18090确属本项目；新增文件端口必须可绑定。
    ids=run(compose+['ps','-q']).split()
    instances=json.loads(run(['docker','inspect']+ids)) if ids else []
    if len(instances)!=2 or any(c['State']['Status']!='running' for c in instances):raise RuntimeError('旧后台实例状态不符合升级前提')
    for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
        s=socket.socket(family,socket.SOCK_STREAM)
        try:
            if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            s.bind((address,18091))
        finally:s.close()
    backup=os.path.join(root,'backups','before-m4-'+datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'))
    os.makedirs(backup,mode=0o700)
    db=sqlite3.connect('file:'+os.path.join(root,'data/control.db')+'?mode=ro',uri=True);db.execute('BEGIN')
    if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise RuntimeError('数据库完整性异常')
    with os.fdopen(os.open(os.path.join(backup,'control.sql'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:
        for line in db.iterdump():out.write(line+'\n')
    db.close()
    shutil.copyfile(os.path.join(root,'data/master.key'),os.path.join(backup,'master.key'));os.chmod(os.path.join(backup,'master.key'),0o600)
    for name,body in old.items():
        with open(os.path.join(backup,name),'w') as out:out.write(body)
        os.chmod(os.path.join(backup,name),0o600)
    run(['docker','load','-i',upload])
    if run(['docker','image','inspect','trojan-control:m4','--format','{{.Id}}'])!='$imageId':raise RuntimeError('升级镜像配置摘要错误')
    shared=os.path.join(root,'run/caddy');os.makedirs(shared,mode=0o770,exist_ok=True);os.chown(shared,0,10001);os.chmod(shared,0o770)
    public=os.path.join(root,'public/demo');os.makedirs(public,mode=0o755,exist_ok=True)
    demo=os.path.join(public,'README.txt')
    if not os.path.exists(demo):
        with open(demo,'x') as out:out.write('Trojan Proxy public directory test fixture.\n')
        os.chmod(demo,0o644)
    changed=True
    for name,body in payload['files'].items():
        path=os.path.join(root,name)
        with open(path+'.new','w') as out:out.write(body)
        os.chmod(path+'.new',0o644);os.replace(path+'.new',path)
    run(compose+['config','--quiet'])
    run(compose+['up','--no-build','-d'])
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    ready=False
    for _ in range(60):
        try:
            with opener.open('http://127.0.0.1:18090/healthz',timeout=2) as response:
                if response.status==200:ready=True;break
        except OSError:pass
        time.sleep(.5)
    if not ready:raise RuntimeError('升级后控制面未就绪')
    time.sleep(6)
    ids=run(compose+['ps','-q']).split();current=json.loads(run(['docker','inspect']+ids))
    control_id=next(c['Id'] for c in current if c['Config']['Labels']['com.docker.compose.service']=='control')
    run(['docker','exec',control_id,'test','-S','/run/caddy/admin.sock'])
    db=sqlite3.connect('file:'+os.path.join(root,'data/control.db')+'?mode=ro',uri=True)
    body=json.loads(db.execute('SELECT body FROM revision_journal WHERE id=1').fetchone()[0]);db.close()
    if not body['applied'].get('gateway') or body.get('pending'):raise RuntimeError('网关初始快照未收敛')
    after=snapshot()
    print(json.dumps({'upgraded':True,'backup_directory':backup,'image_id':'$imageId','control_ready':True,'gateway_reconciled':True,'existing_unrelated_containers_unchanged':all(after.get(k)==v for k,v in before.items())},ensure_ascii=False))
except Exception:
    if changed:
        for name,body in old.items():
            with open(os.path.join(root,name),'w') as out:out.write(body)
        run(compose+['up','--no-build','-d'])
    raise
finally:
    if os.path.exists(upload):os.unlink(upload)
"@
    $script | ssh -T -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes $Server 'python3 -'
    $result=$LASTEXITCODE
} finally {
    if(Test-Path -LiteralPath $probeKey){Remove-Item -LiteralPath $probeKey -Force}
    Remove-Item -LiteralPath $probeDir -Force
}
exit $result
