"""恢复摘要、SQLite完整性、配额、空目录与认证/维护锁的定向破坏。"""
import json
from pathlib import Path
import shutil
import subprocess
import uuid

root=Path(__file__).resolve().parents[2]
target=root/'.work/recovery-mutations'/uuid.uuid4().hex[:10]
cases=[
    ('archive-digest','internal/recovery/restore.go','if hex.EncodeToString(h.Sum(nil)) != expected {','if false && hex.EncodeToString(h.Sum(nil)) != expected {','internal/recovery','TestRestoreRejectsBadDigestArchiveAndLiveControl','unsafe backup accepted'),
    ('sqlite-integrity','internal/recovery/database.go','err != nil || integrity != "ok"','false && (err != nil || integrity != "ok")','internal/recovery','TestRestoreIntegrityCheckIsIndependentOfReadableAccountTables','independent SQLite integrity check did not reject'),
    ('quota','internal/recovery/restore.go','header.Size > limit','false && header.Size > limit','internal/recovery','TestRestoreQuotaAndUnrelatedNonemptyDirectory','oversized valid JSON bypassed archive quota'),
    ('empty-target','internal/recovery/restore.go','if err = emptyRestoreTarget(c.DataDir); err != nil {','if err = emptyRestoreTarget(c.DataDir); false {','internal/recovery','TestRestoreQuotaAndUnrelatedNonemptyDirectory','cold restore touched nonempty user directory'),
    ('restore-auth-gate','cmd/control/bootstrap.go','if _, err := os.Lstat(filepath.Join(directory, "recovery-required")); err == nil {','if _, err := os.Lstat(filepath.Join(directory, "recovery-required")); false {','cmd/control','TestColdRestoreCannotServeOldAuthentication','cold restore allowed old authentication before rebinding'),
    ('exclusive-lock','internal/maintenance/lock.go','lockFile(f, exclusive)','lockFile(f, false)','internal/maintenance','TestSharedControlAndExclusiveRecoveryCannotOverlap','recovery overlapped running control'),
]
report={}
for name,filename,old,new,package,test,reason in cases:
    directory=target/name
    for folder in ('internal','cmd'):shutil.copytree(root/folder,directory/folder)
    for module in ('go.mod','go.sum'):shutil.copyfile(root/module,directory/module)
    path=directory/filename;source=path.read_text(encoding='utf-8')
    assert source.count(old)==1,(name,source.count(old))
    path.write_text(source.replace(old,new),encoding='utf-8')
    result=subprocess.run(['go','test','-C',str(directory),'./'+package,'-run','^'+test+'$','-count=1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,encoding='utf-8',timeout=90)
    assert result.returncode!=0 and reason in result.stdout,(name,result.returncode,result.stdout)
    report[name]={'passed':True,'expected_failure':reason}
print(json.dumps({'passed':True,'mutations':report},ensure_ascii=False,indent=2))
