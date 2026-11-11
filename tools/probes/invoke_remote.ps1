param(
    [Parameter(Mandatory=$true)][string]$Server,
    [Parameter(Mandatory=$true)][string]$KeyPath,
    [Parameter(Mandatory=$true)][ValidateSet('gateway_probe','tls_probe','binary_probe','health_probe')][string]$Probe,
    [string]$BinaryPath,
    [string]$BinaryArgs = ''
)
$ErrorActionPreference = 'Stop'
# 原密钥不改权限；临时目录先限制 ACL，再复制密钥。
$probeDir = Join-Path $env:TEMP ('trojan-probe-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $probeDir | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
icacls $probeDir /inheritance:r /grant:r "${identity}:(OI)(CI)F" | Out-Null
if ($LASTEXITCODE -ne 0) { throw '临时目录权限设置失败' }
$probeKey = Join-Path $probeDir 'identity.pem'
try {
    Copy-Item -LiteralPath $KeyPath -Destination $probeKey
    $sources = @{}
    if ($Probe -eq 'binary_probe') {
        if (-not $BinaryPath) { throw 'binary_probe 必须指定 BinaryPath' }
        $remoteBinary = '/tmp/trojan-binary-' + [guid]::NewGuid().ToString('N')
        scp -C -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes $BinaryPath "${Server}:$remoteBinary"
        if ($LASTEXITCODE -ne 0) { throw 'SCP 上传失败' }
        $argsEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($BinaryArgs))
        $sources['binary_probe.py'] = @"
import base64,os,subprocess,json,shlex
path='$remoteBinary'
try:
    os.chmod(path,0o700)
    args=shlex.split(base64.b64decode('$argsEncoded').decode('utf-8'))
    result=subprocess.run([path]+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=60)
    print(json.dumps({'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr},ensure_ascii=False))
    if result.returncode: raise SystemExit(result.returncode)
finally:
    os.unlink(path)
"@
    } else {
        foreach ($name in @('gateway_probe', $Probe) | Select-Object -Unique) {
            $sources["$name.py"] = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "$name.py")
        }
    }
    $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($sources | ConvertTo-Json -Compress)))
    # 仅传输探针源码；远端临时目录由 Python 上下文退出时清理。
    $bootstrap = @"
import base64,json,tempfile,sys,runpy,os
with tempfile.TemporaryDirectory(prefix='trojan-probe-src-') as directory:
    for name,source in json.loads(base64.b64decode('$payload').decode('utf-8')).items():
        with open(os.path.join(directory,name),'w') as output: output.write(source)
    sys.path.insert(0,directory)
    sys.argv=['$Probe.py']
    runpy.run_path(os.path.join(directory,'$Probe.py'),run_name='__main__')
"@
    $bootstrap | ssh -i $probeKey -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=yes $Server 'python3 -'
    $probeExit = $LASTEXITCODE
} finally {
    if (Test-Path -LiteralPath $probeKey) { Remove-Item -LiteralPath $probeKey -Force }
    Remove-Item -LiteralPath $probeDir -Force
}
exit $probeExit
