"""确认绑定、保存一致性初始化快照，再启动本项目后台；不读取或输出凭据。"""
import datetime
import json
import os
import shutil
import socket
import sqlite3
import time
import urllib.request
import urllib.error
from gateway_probe import command,running_snapshot

directory='/opt/trojan-proxy-refactor'
database=os.path.join(directory,'data/control.db')
before=running_snapshot()
if not os.path.isfile(os.path.join(directory,'.managed-by-trojan-refactor')):
    raise RuntimeError('部署标记缺失')
connection=sqlite3.connect('file:'+database+'?mode=ro',uri=True)
connection.execute('BEGIN')
count=connection.execute('SELECT COUNT(*) FROM administrator WHERE id=1').fetchone()[0]
if count!=1: raise RuntimeError('管理员绑定尚未保存')
integrity=connection.execute('PRAGMA integrity_check').fetchone()[0]
if integrity!='ok': raise RuntimeError('初始化数据库完整性检查失败')
backup=os.path.join(directory,'backups','enrollment-'+datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ'))
os.makedirs(backup,mode=0o700)
with os.fdopen(os.open(os.path.join(backup,'control.sql'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as output:
    for line in connection.iterdump(): output.write(line+'\n')
connection.close()
shutil.copyfile(os.path.join(directory,'data/master.key'),os.path.join(backup,'master.key'))
os.chmod(os.path.join(backup,'master.key'),0o600)
handles=[]
try:
    for port in (8007,18090):
        for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
            handle=socket.socket(family,socket.SOCK_STREAM);handles.append(handle)
            if family==socket.AF_INET6:handle.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            handle.bind((address,port))
finally:
    for handle in handles:handle.close()
compose=['docker','compose','-p','trojan-refactor','-f',os.path.join(directory,'compose.admin.yaml')]
image=command(['docker','image','inspect','trojan-control:dev','--format','{{.Id}}'])
if image!='sha256:d9ff323643a2b86415bc792df539062368c193c9e265a4a67ed3a5441a5745d8':raise RuntimeError('启动镜像与已验证版本不符')
command(compose+['up','--no-build','-d','control'])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
ready=False
for attempt in range(40):
    try:
        with opener.open('http://127.0.0.1:18090/healthz',timeout=2) as response:
            if response.status==200:ready=True;break
    except (OSError,urllib.error.URLError):pass
    time.sleep(.5)
if not ready:raise RuntimeError('控制面健康检查未就绪，未启动公网入口')
command(compose+['up','--no-build','-d','admin-gateway'])
after=running_snapshot()
print(json.dumps({'account_initialized':True,'database_integrity':integrity,'backup_directory':backup,
    'control_ready':True,'gateway_started':True,'existing_containers_unchanged':all(after.get(k)==v for k,v in before.items())},ensure_ascii=False))
