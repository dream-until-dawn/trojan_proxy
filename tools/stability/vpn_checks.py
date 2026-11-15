"""共享443长稳契约：公开入口与私有引擎不能混为同一个验证目标。"""
from checks import CheckFailure

def private_listener_records(port,tables):
    if type(port) is not int or not 1024<=port<=65535: raise CheckFailure('invalid_private_vpn_port')
    listeners=[]
    for family,body in tables.items():
        for line in body.splitlines()[1:]:
            fields=line.split()
            if not fields: continue
            if len(fields)<4: raise CheckFailure('invalid_listener_table')
            if fields[3]!='0A': continue
            address,raw_port=fields[1].rsplit(':',1)
            if int(raw_port,16)!=port: continue
            listeners.append('127.0.0.1' if family=='tcp' and address=='0100007F' else 'non_loopback_or_ipv6')
    if listeners!=['127.0.0.1']: raise CheckFailure('private_vpn_listener_not_loopback_only')
    return {'port':port,'addresses':listeners}

def check_private_listener(port):
    tables={}
    for family in ('tcp','tcp6'):
        try:
            with open('/proc/net/'+family) as source:body=source.read(2*1024*1024+1)
        except FileNotFoundError:
            if family=='tcp6':continue
            raise
        if len(body)>2*1024*1024:raise CheckFailure('listener_table_exceeds_budget')
        tables[family]=body
    return private_listener_records(port,tables)
