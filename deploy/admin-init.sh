#!/bin/sh
# 首次初始化仅供服务所有者在交互终端运行，秘密不经Web或日志分发。
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec docker compose -p trojan-refactor -f compose.admin.yaml run --rm --no-deps \
  --entrypoint proxyctl control admin-init --config /etc/trojan-proxy/proxy.json
