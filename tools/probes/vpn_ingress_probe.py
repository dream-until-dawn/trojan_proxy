"""只读采样本项目两端口的入站包计数；不记录地址、认证或业务载荷。"""
import json
import socket
import struct
import time

# 与本阶段已部署入口对应；不扫描其他端口，不改防火墙。
counts = {8007: {'packets': 0, 'syn': 0, 'payload_packets': 0},
          18443: {'packets': 0, 'syn': 0, 'payload_packets': 0}}
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as stream:
    stream.settimeout(1)
    print(json.dumps({'capture_ready': True, 'duration_seconds': 30}), flush=True)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            packet = stream.recv(65535)
        except socket.timeout:
            continue
        if len(packet) < 40 or packet[0] >> 4 != 4:
            continue
        offset = (packet[0] & 15) * 4
        if offset < 20 or len(packet) < offset + 20:
            continue
        destination = struct.unpack('!H', packet[offset + 2:offset + 4])[0]
        if destination not in counts or packet[12] == 127:
            continue
        header = (packet[offset + 12] >> 4) * 4
        entry = counts[destination]
        entry['packets'] += 1
        entry['syn'] += int(bool(packet[offset + 13] & 2))
        entry['payload_packets'] += int(len(packet) > offset + header)
print(json.dumps({'duration_seconds': 30, 'ipv4_inbound': counts}))
