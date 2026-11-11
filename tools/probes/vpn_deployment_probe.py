"""并行VPN部署前只读盘点，端口探测结束立即释放，不改现有容器。"""
import hashlib
import json
import os
import socket
import ssl
import subprocess

def run(args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=20)
    if result.returncode:raise RuntimeError(result.stderr[-1000:])
    return result.stdout.strip()

root='/opt/trojan-proxy-refactor'
report={'managed':os.path.isfile(os.path.join(root,'.managed-by-trojan-refactor')),'files':{},'ports':{}}
report['staged_uploads']=[{'name':name,'bytes':os.stat('/tmp/'+name).st_size} for name in os.listdir('/tmp') if name.startswith('trojan-m6-') and name.endswith('.tar.gz') and os.path.isfile('/tmp/'+name)]
for name in ('compose.admin.yaml','Caddyfile.admin','admin.proxy.example.json'):
    with open(os.path.join(root,name),'rb') as stream:report['files'][name]=hashlib.sha256(stream.read()).hexdigest()
for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
    connection=socket.socket(family,socket.SOCK_STREAM)
    try:
        if family==socket.AF_INET6:connection.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        connection.bind((address,18443));report['ports'][address]=True
    except OSError:report['ports'][address]=False
    finally:connection.close()
ids=run(['docker','ps','-q']).split()
report['own_containers']=[]
for container in json.loads(run(['docker','inspect']+ids)) if ids else []:
    if container['Config'].get('Labels',{}).get('com.docker.compose.project')=='trojan-refactor' or container['Name']=='/trojan':
        report['own_containers'].append({'id':container['Id'],'name':container['Name'],'image':container['Image'],'started':container['State']['StartedAt'],'restart_count':container['RestartCount'],'user':container['Config'].get('User','')})
report['certificate']=ssl._ssl._test_decode_cert('/mnt/trojan/cert/qin-xin.top/fullchain.cer')
report['memory']=run(['free','-m'])
report['disk']=run(['df','-h',root])
print(json.dumps(report,ensure_ascii=False,indent=2))
