"""明确验证根模块和独立引擎，避免go test ./...漏掉嵌套Go模块。"""
from pathlib import Path
import subprocess

root=Path(__file__).resolve().parents[1]
for module in (root,root/'engines/trojan'):
    for args in (['go','test','./...'],['go','vet','./...']):
        print('验证模块:',module.relative_to(root) if module!=root else '.', '命令:',' '.join(args),flush=True)
        subprocess.run(args,cwd=module,check=True)
