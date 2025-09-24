#!/bin/bash
source ./component/utils.sh
source ./component/acme.install.sh
source ./component/trojan.manage.sh
source ./component/nginx.manage.sh

set -euo pipefail

info "开始安装必要程序...域名:${DOMAIN},邮箱:${EMAIL},trojan密码:${TROJAN_PW}"
install_latest_acme
install_latest_trojan

start_nginx
start_trojan

wait