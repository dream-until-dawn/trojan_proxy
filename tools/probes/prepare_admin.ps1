param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$KeyPath,
    [switch]$ReuseLoadedImage
)
$ErrorActionPreference='Stop'
$repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$archive=Join-Path $repoRoot '.work/control-image.tar.gz'
$archiveHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
# Docker Desktop可能返回OCI索引ID，旧版Engine返回配置ID；从已导出包计算统一配置摘要。
$tarPath=Join-Path $repoRoot '.work/control-image.tar'
$imageId=@'
import sys,tarfile,json,hashlib
with tarfile.open(sys.argv[1]) as archive:
    entries=json.load(archive.extractfile('manifest.json'))
    entry=next(e for e in entries if 'trojan-control:dev' in e.get('RepoTags',[]))
    print('sha256:'+hashlib.sha256(archive.extractfile(entry['Config']).read()).hexdigest())
'@ | python - $tarPath
if ($LASTEXITCODE -ne 0) { throw '镜像配置摘要计算失败' }
$reuseValue=if ($ReuseLoadedImage) {'True'} else {'False'}
$files=@{}
foreach ($name in @('compose.admin.yaml','Caddyfile.admin','admin.proxy.example.json','admin-init.sh')) {
    $files[$name]=(Get-Content -Raw -LiteralPath (Join-Path $repoRoot "deploy/$name")).Replace("`r`n","`n")
}
# 此脚本只接受历史认证阶段包，避免将后续含新挂载的配置作为全新部署误用。
if ($files['compose.admin.yaml'] -notmatch 'image: trojan-control:dev') { throw '当前是M4工作树，已有部署使用upgrade_admin.ps1；全新部署请等待正式安装器' }
$payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($files | ConvertTo-Json -Compress)))
$probeDir=Join-Path $env:TEMP ('trojan-install-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $probeDir | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $probeDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw '临时目录权限设置失败' }
$probeKey=Join-Path $probeDir 'identity.pem'
$remoteArchive='/tmp/trojan-control-image-'+[guid]::NewGuid().ToString('N')+'.tar.gz'
try {
    Copy-Item -LiteralPath $KeyPath -Destination $probeKey
    if (-not $ReuseLoadedImage) {
        scp -C -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes $archive "${Server}:$remoteArchive"
        if ($LASTEXITCODE -ne 0) { throw '镜像传输失败' }
    }
    $script=@"
import os,json,base64,hashlib,subprocess,socket
def run(args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=90)
    if result.returncode: raise RuntimeError(result.stderr)
    return result.stdout.strip()
def snapshot():
    ids=run(['docker','ps','-q']).split()
    return {c['Id']:c['State']['StartedAt'] for c in json.loads(run(['docker','inspect']+ids))} if ids else {}
before=snapshot()
upload='$remoteArchive'
directory='/opt/trojan-proxy-refactor'
try:
    if not ${reuseValue}:
        with open(upload,'rb') as stream: actual=hashlib.sha256(stream.read()).hexdigest()
        if actual!='$archiveHash': raise RuntimeError('镜像包摘要不匹配')
    else:
        if run(['docker','image','inspect','trojan-control:dev','--format','{{.Id}}'])!='$imageId':
            raise RuntimeError('已有镜像配置摘要不匹配，必须重新传输')
    marker=os.path.join(directory,'.managed-by-trojan-refactor')
    if os.path.exists(directory) and os.listdir(directory) and not os.path.isfile(marker):
        raise RuntimeError('目标目录非空且不属于本项目，拒绝覆盖')
    # 仅预检后台和内控端口，不触碰既有服务80/443。
    handles=[]
    try:
        for port in (8007,18090):
            for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
                handle=socket.socket(family,socket.SOCK_STREAM);handles.append(handle)
                if family==socket.AF_INET6: handle.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                handle.bind((address,port))
    finally:
        for handle in handles: handle.close()
    os.makedirs(directory,mode=0o700,exist_ok=True)
    if not os.path.exists(marker):
        with open(marker,'x') as output: output.write('trojan-refactor-admin-v1\n')
        os.chmod(marker,0o600)
    for name,body in json.loads(base64.b64decode('$payload').decode('utf-8')).items():
        path=os.path.join(directory,name)
        if os.path.exists(path):
            with open(path) as existing:
                if existing.read()!=body: raise RuntimeError('部署文件已修改，拒绝覆盖: '+name)
        else:
            with open(path,'x') as output: output.write(body)
            os.chmod(path,0o700 if name.endswith('.sh') else 0o644)
    data=os.path.join(directory,'data')
    if not os.path.exists(data):
        os.mkdir(data,0o700);os.chown(data,10001,10001)
    if os.stat(data).st_uid!=10001: raise RuntimeError('数据目录权限与容器用户不匹配')
    if not ${reuseValue}: run(['docker','load','-i',upload])
    loaded=run(['docker','image','inspect','trojan-control:dev','--format','{{.Id}}'])
    if loaded!='$imageId': raise RuntimeError('导入镜像ID不匹配')
    run(['docker','compose','-p','trojan-refactor','-f',os.path.join(directory,'compose.admin.yaml'),'config','--quiet'])
    run(['docker','image','inspect','caddy@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9'])
    after=snapshot()
    print(json.dumps({'prepared':True,'directory':directory,'image_id':loaded,'services_started':False,'account_database_exists':os.path.exists(os.path.join(data,'control.db')),'existing_containers_unchanged':all(after.get(k)==v for k,v in before.items()),'next_command':directory+'/admin-init.sh'},ensure_ascii=False))
finally:
    if os.path.exists(upload): os.unlink(upload)
"@
    $script | ssh -T -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes $Server 'python3 -'
    $result=$LASTEXITCODE
} finally {
    if (Test-Path -LiteralPath $probeKey) { Remove-Item -LiteralPath $probeKey -Force }
    Remove-Item -LiteralPath $probeDir -Force
}
exit $result
