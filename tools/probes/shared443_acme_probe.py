"""共享listener开启时验证多域HTTP-01、短期续期、Host/WS及后台候选隔离。"""
import os,runpy
from pathlib import Path
os.environ['TROJAN_SHARED443_TEST']='1'
runpy.run_path(str(Path(__file__).with_name('multidomain_probe.py')),run_name='__main__')
