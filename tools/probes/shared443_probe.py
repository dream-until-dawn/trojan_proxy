"""复用真实VPN夹具，通过生产编译器生成的共享443入口执行相同正反向断言。"""
import os,runpy
from pathlib import Path
os.environ['TROJAN_SHARED443_PROBE']='1'
runpy.run_path(str(Path(__file__).with_name('vpn_egress_probe.py')),run_name='__main__')
