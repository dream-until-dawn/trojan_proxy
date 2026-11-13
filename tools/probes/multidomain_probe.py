"""复用真实Pebble夹具，逐域验证HTTP-01与Host隔离，不访问公共CA。"""
import os,runpy
from pathlib import Path
os.environ['TROJAN_MULTI_HOST']='1'
runpy.run_path(str(Path(__file__).with_name('acme_lifecycle_probe.py')),run_name='__main__')
