"""当前产品网关镜像选择；每轮探针解析为不可变本地ID，不隐式拉取镜像。"""
import os
import subprocess

OPENSSL_IMAGE='alpine/openssl@sha256:f6def4887e8413b228b66f314d0bcf5c25b128d918a258f3b0b9d66a0327edcb'

def resolve(target):
    result=subprocess.run(['docker','image','inspect',target,'--format','{{.Id}}'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True,timeout=20)
    if result.returncode:raise RuntimeError('探针镜像不存在，请先构建产品或准备固定夹具: '+target)
    return result.stdout.strip()

def gateway_image():
    return resolve(os.environ.get('TROJAN_GATEWAY_IMAGE','trojan-gateway:dev'))

def control_image():
    return resolve(os.environ.get('TROJAN_CONTROL_IMAGE','trojan-control:m6'))

def openssl_image():
    return resolve(OPENSSL_IMAGE)

def container_logs(container):
    """Docker日志通常写stderr，不能只读取stdout而丢失真实失败原因。"""
    result=subprocess.run(['docker','logs',container],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True,timeout=10)
    return result.stdout
