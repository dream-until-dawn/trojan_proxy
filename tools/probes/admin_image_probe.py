"""比较准备镜像的内容身份，不读取账户或业务环境变量。"""
import json
from gateway_probe import command

meta=json.loads(command(['docker','image','inspect','trojan-control:dev']))[0]
print(json.dumps({'id':meta['Id'],'layers':meta['RootFS']['Layers'],
    'user':meta['Config']['User'],'entrypoint':meta['Config']['Entrypoint'],
    'binaries':command(['docker','run','--rm','--network','none','--read-only',
        '--cap-drop','ALL','--entrypoint','sha256sum','trojan-control:dev',
        '/usr/local/bin/control','/usr/local/bin/proxyctl'])},ensure_ascii=False,indent=2))

print(json.dumps({'admin_init_shell_syntax':command(['sh','-n','/opt/trojan-proxy-refactor/admin-init.sh']),
    'gateway_configuration':command(['docker','run','--rm','--network','none','--read-only',
        '--cap-drop','ALL','--tmpfs','/run/caddy','--tmpfs','/data','--tmpfs','/config',
        '-v','/opt/trojan-proxy-refactor/Caddyfile.admin:/etc/caddy/Caddyfile:ro',
        '-v','/mnt/trojan/cert/qin-xin.top:/certs:ro',
        'caddy@sha256:78bd35025c7ba85961dd149ae670315129954e77abe2383ac47c89106b35ade9',
        'caddy','validate','--config','/etc/caddy/Caddyfile'])},ensure_ascii=False))
