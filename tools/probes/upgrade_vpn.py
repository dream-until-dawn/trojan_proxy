"""已验证M4基线升级到并行VPN；由PowerShell注入非秘密payload，仅操作本项目。"""
import datetime
import hashlib
import http.client
import json
import os
import shutil
import socket
import sqlite3
import stat
import subprocess
import time
import urllib.request

root='/opt/trojan-proxy-refactor'
compose=['docker','compose','-p','trojan-refactor','-f',os.path.join(root,'compose.admin.yaml')]
report={}
old={}
changed=False

def run(args,timeout=90):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=timeout)
    if result.returncode:raise RuntimeError('命令失败 '+str(args[:3])+': '+result.stderr[-1000:])
    return result.stdout.strip()

def untouched():
    ids=run(['docker','ps','-q']).split()
    result={}
    for container in json.loads(run(['docker','inspect']+ids)) if ids else []:
        labels=container['Config'].get('Labels',{})
        # 旧Trojan、其他业务，以及当前Caddy后台网关都必须保持原进程。
        if labels.get('com.docker.compose.project')!='trojan-refactor' or labels.get('com.docker.compose.service')=='admin-gateway':
            result[container['Id']]=container['State']['StartedAt']
    return result

def safe_directory(relative,uid,gid,mode):
    target=os.path.join(root,relative)
    os.makedirs(target,mode=mode,exist_ok=True)
    if os.path.islink(target) or not os.path.isdir(target):raise RuntimeError('部署目录不是普通目录: '+relative)
    os.chown(target,uid,gid);os.chmod(target,mode)
    return target

def write_file(path,body,mode=0o600):
    if os.path.lexists(path) and not stat.S_ISREG(os.lstat(path).st_mode):raise RuntimeError('拒绝覆盖非普通文件')
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,mode)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(body);stream.flush();os.fsync(stream.fileno())
    os.chmod(path,mode)

def healthy():
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline=time.time()+30
    while time.time()<deadline:
        try:
            with opener.open('http://127.0.0.1:18090/healthz',timeout=2) as response:
                if response.status==200:return
        except Exception:pass
        time.sleep(.5)
    raise RuntimeError('控制服务未通过健康检查')

before=untouched()
try:
    if os.path.realpath(root)!=root or not os.path.isfile(os.path.join(root,'.managed-by-trojan-refactor')):raise RuntimeError('目标不是固定受管部署')
    digest=hashlib.sha256()
    with open(payload['upload'],'rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    if digest.hexdigest()!=payload['sha256']:raise RuntimeError('升级包摘要不符')
    for name,expected in payload['expected'].items():
        with open(os.path.join(root,name),'rb') as stream:body=stream.read()
        if hashlib.sha256(body).hexdigest()!=expected:raise RuntimeError('部署配置偏离M4基线: '+name)
        old[name]=body
    ids=run(compose+['ps','-q']).split()
    instances=json.loads(run(['docker','inspect']+ids)) if ids else []
    if len(instances)!=2 or any(c['State']['Status']!='running' for c in instances):raise RuntimeError('旧后台实例状态不符合升级前提')
    control=next(c for c in instances if c['Config']['Labels']['com.docker.compose.service']=='control')
    if control['Image']!='sha256:5c569b2a6cc2cd45078aa909a1cb03f0a05ca90a7b938658eb238cb824ddbf5c':raise RuntimeError('旧控制镜像偏离M4')
    for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
        connection=socket.socket(family,socket.SOCK_STREAM)
        try:
            if family==socket.AF_INET6:connection.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            connection.bind((address,18443))
        finally:connection.close()
    if shutil.disk_usage(root).free<512*1024*1024:raise RuntimeError('可用磁盘不足512MiB')
    backup=os.path.join(root,'backups','before-m6-'+datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'))
    os.makedirs(backup,mode=0o700)
    db=sqlite3.connect('file:'+os.path.join(root,'data/control.db')+'?mode=ro',uri=True);db.execute('BEGIN')
    if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise RuntimeError('数据库完整性异常')
    with os.fdopen(os.open(os.path.join(backup,'control.sql'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as output:
        for line in db.iterdump():output.write(line+'\n')
        output.flush();os.fsync(output.fileno())
    db.close()
    shutil.copyfile(os.path.join(root,'data/master.key'),os.path.join(backup,'master.key'));os.chmod(os.path.join(backup,'master.key'),0o600)
    for name,body in old.items():write_file(os.path.join(backup,name),body)
    report['backup']=backup
    run(['docker','load','-i',payload['upload']],timeout=180)
    for tag,expected in payload['images'].items():
        if run(['docker','image','inspect',tag,'--format','{{.Id}}'])!=expected:raise RuntimeError('镜像配置摘要不符: '+tag)
    safe_directory('certificates',0,10001,0o750)
    imported=safe_directory('certificates/imported',0,10001,0o750)
    safe_directory('certificates/published',10001,10001,0o750)
    safe_directory('run/vpn',10002,10001,0o770)
    for source,target in [('fullchain.cer','fullchain.cer'),('private.key','private.key')]:
        with open('/mnt/trojan/cert/qin-xin.top/'+source,'rb') as stream:body=stream.read(1024*1024+1)
        if len(body)>1024*1024:raise RuntimeError('导入证书材料过大')
        path=os.path.join(imported,target);write_file(path,body,0o640);os.chown(path,0,10001)
    changed=True
    for name,body in payload['files'].items():write_file(os.path.join(root,name),body.encode('utf-8'))
    run(compose+['config','--quiet'])
    run(compose+['up','-d','--no-deps','vpn-runner','control'])
    healthy()
    control_id=run(compose+['ps','-q','control'])
    runner_id=run(compose+['ps','-q','vpn-runner'])
    report['certificate']=json.loads(run(['docker','exec',control_id,'proxyctl','certificate-check','--config','/etc/trojan-proxy/proxy.json']))
    connection=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);connection.settimeout(5);connection.connect(os.path.join(root,'run/vpn/control.sock'))
    connection.sendall(b'GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    response=http.client.HTTPResponse(connection);response.begin()
    if response.status!=200:raise RuntimeError('VPN执行器状态不可读')
    report['runner']=json.loads(response.read().decode('utf-8'));connection.close()
    db=sqlite3.connect('file:'+os.path.join(root,'data/control.db')+'?mode=ro',uri=True)
    journal=json.loads(db.execute('SELECT body FROM revision_journal WHERE id=1').fetchone()[0]);db.close()
    if journal.get('pending') is not None:raise RuntimeError('升级后存在待恢复修订')
    report['revision']=journal['applied']['number']
    if untouched()!=before:raise RuntimeError('其他业务或Caddy后台网关进程发生变化')
    report['untouched_containers_verified']=True
    report['containers']={'control':control_id,'runner':runner_id}
    report['images']=payload['images']
    report['passed']=True
except Exception as error:
    report['error']=str(error)
    if changed:
        try:
            # 无新版业务提交才自动回退，避免旧镜像误解新VPN密文或覆盖所有者操作。
            db=sqlite3.connect('file:'+os.path.join(root,'data/control.db')+'?mode=ro',uri=True)
            journal=json.loads(db.execute('SELECT body FROM revision_journal WHERE id=1').fetchone()[0]);db.close()
            if journal['applied'].get('vpn') or journal.get('pending'):raise RuntimeError('已有新版VPN修订，保留新服务与备份，须按当前修订修复')
            run(compose+['stop','vpn-runner']);run(compose+['rm','-f','vpn-runner'])
            for name,body in old.items():write_file(os.path.join(root,name),body)
            run(compose+['up','-d','--no-deps','control']);healthy()
            report['rolled_back']=True
        except Exception as rollback_error:report['rollback_error']=str(rollback_error)
finally:
    if os.path.isfile(payload['upload']):os.unlink(payload['upload'])
print(json.dumps(report,ensure_ascii=False,indent=2))
raise SystemExit(0 if report.get('passed') else 1)
