"""当前产品网关镜像选择；每轮探针解析为不可变本地ID，不隐式拉取镜像。"""
import os
import subprocess

def gateway_image():
    target=os.environ.get('TROJAN_GATEWAY_IMAGE','trojan-gateway:dev')
    result=subprocess.run(['docker','image','inspect',target,'--format','{{.Id}}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=20)
    if result.returncode:raise RuntimeError('受限网关镜像不存在，请先构建deploy/Dockerfile.gateway')
    return result.stdout.strip()

def container_logs(container):
    """Docker日志通常写stderr，不能只读取stdout而丢失真实失败原因。"""
    result=subprocess.run(['docker','logs',container],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True,timeout=10)
    return result.stdout
