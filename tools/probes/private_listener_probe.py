"""仅回环引擎仍可经共享443代理；非回环IPv4与IPv6不能直连旧端口。"""
import os,runpy
from pathlib import Path
os.environ['TROJAN_PRIVATE_VPN_LISTENER']='1'
runpy.run_path(str(Path(__file__).with_name('shared443_probe.py')),run_name='__main__')
