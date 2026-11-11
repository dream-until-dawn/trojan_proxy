param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$KeyPath
)
$ErrorActionPreference='Stop'
$repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$archive=Join-Path $repoRoot '.work/m6-images.tar.gz'
$archiveHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
$gate=Get-Content -Raw -LiteralPath (Join-Path $repoRoot '.work/m6-gate.json') | ConvertFrom-Json
if(-not $gate.passed -or $gate.archive_sha256 -ne $archiveHash){throw '部署前门槛未通过或升级包已变化，先运行tools/release/gate.py'}
$head=(git -C $repoRoot rev-parse HEAD).Trim()
if($LASTEXITCODE -ne 0 -or $head -ne $gate.commit){throw '源码提交已变化，请重新生成部署前门槛'}
$dirty=git -C $repoRoot status --porcelain
if($LASTEXITCODE -ne 0 -or $dirty){throw '工作区已变化，请重新提交并生成部署前门槛'}
$images=@'
import sys,tarfile,json,hashlib
with tarfile.open(sys.argv[1]) as archive:
    manifest=json.load(archive.extractfile('manifest.json'))
    print(json.dumps({tag:'sha256:'+hashlib.sha256(archive.extractfile(entry['Config']).read()).hexdigest() for entry in manifest for tag in entry.get('RepoTags',[])}))
'@ | python - $archive
if($LASTEXITCODE -ne 0){throw '升级包镜像摘要读取失败'}
$imageMap=$images | ConvertFrom-Json
if(@($imageMap.PSObject.Properties).Count -ne @($gate.images.PSObject.Properties).Count){throw '升级包镜像数量与门槛不同'}
foreach($entry in $gate.images.PSObject.Properties){if($imageMap.($entry.Name) -ne $entry.Value){throw '升级包镜像与安全门槛不同'}}
$files=@{}
foreach($name in @('compose.admin.yaml','Caddyfile.admin','admin.proxy.example.json')){$files[$name]=(Get-Content -Raw -LiteralPath (Join-Path $repoRoot "deploy/$name")).Replace("`r`n","`n")}
$expected=@{
 'compose.admin.yaml'='3435e9aeccda880d938ac7042439ce67e787f7f307423c7540f437befe7c1064'
 'Caddyfile.admin'='1a64211e6c09b77c26cfd8680a58bed1b315eeda82fd25eed4a1b69e7d47d7e2'
 'admin.proxy.example.json'='d8be9980fcbc9c8d07012bdc4b042eb71aeb6859b4f1a414d391a3592e9ecf5a'
}
$remoteArchive='/tmp/trojan-m6-'+[guid]::NewGuid().ToString('N')+'.tar.gz'
$payload=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((@{files=$files;expected=$expected;upload=$remoteArchive;sha256=$archiveHash;images=$imageMap;commit=$gate.commit} | ConvertTo-Json -Depth 8 -Compress)))
$probeDir=Join-Path $env:TEMP ('trojan-upgrade-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $probeDir | Out-Null
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $probeDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if($LASTEXITCODE -ne 0){throw '密钥临时目录权限设置失败'}
$probeKey=Join-Path $probeDir 'identity.pem'
try {
    Copy-Item -LiteralPath $KeyPath -Destination $probeKey
    scp -C -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes $archive "${Server}:$remoteArchive"
    if($LASTEXITCODE -ne 0){throw '升级包传输失败；尚未改变部署'}
    $script="import base64,json`npayload=json.loads(base64.b64decode('$payload').decode('utf-8'))`n"+(Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'upgrade_vpn.py'))
    $script | ssh -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes $Server 'python3 -'
    if($LASTEXITCODE -ne 0){throw '并行VPN升级未完成，请检查上方恢复报告'}
} finally {
    if(Test-Path -LiteralPath $probeKey){Remove-Item -LiteralPath $probeKey -Force}
    Remove-Item -LiteralPath $probeDir -Force
}
