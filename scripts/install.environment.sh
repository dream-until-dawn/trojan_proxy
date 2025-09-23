#!/bin/bash
source ./component/untill.sh
source ./component/acme.install.sh
source ./component/trojan.manage.sh
source ./component/nginx.manage.sh

set -euo pipefail

info "开始安装acme.sh...邮箱地址: ${EMAIL}"

# if start_acme; then
#     info "acme.sh安装成功"
# else
#     error "acme.sh安装失败"
#     exit 1
# fi

install_latest_trojan

nginx_start

wait