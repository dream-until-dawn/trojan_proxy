"""核实获授权域名、后台候选端口和现有证书元数据，不读取私钥。"""
import json
import socket
from gateway_probe import command

result = {'domain': 'qin-xin.top', 'ports': []}
result['resolved_addresses'] = sorted(set(x[4][0] for x in socket.getaddrinfo('qin-xin.top',443)))
for port in range(8008,7999,-1):
    sockets = []
    item = {'port':port,'available':True}
    try:
        for family,address in [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]:
            sock=socket.socket(family,socket.SOCK_STREAM)
            sockets.append(sock)
            if family==socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((address,port))
    except OSError as error:
        item['available']=False
        item['reason']=str(error)
    finally:
        for sock in sockets: sock.close()
    result['ports'].append(item)
    if item['available']:
        result['selected_admin_port']=port
        break
result['certificate_metadata']=command(['docker','exec','trojan','openssl','x509',
    '-in','/usr/src/trojan-cert/qin-xin.top/fullchain.cer','-noout','-dates','-issuer','-subject','-fingerprint','-sha256'])
print(json.dumps(result,ensure_ascii=False,indent=2))
