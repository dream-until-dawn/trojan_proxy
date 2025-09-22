#!/bin/bash
source ./untill.sh
source ./install.acme.sh

set -e  # 遇到错误立即退出

info "开始安装acme.sh...邮箱地址: ${EMAIL}" 

start_acme

info "启动nginx..."
nginx -g "daemon off;" & # 启动 Nginx
# 等待nginx启动完成
sleep 2
# 检查nginx是否启动成功
if pgrep nginx > /dev/null; then
    success "Nginx启动成功"
else
    error "Nginx启动失败"
    exit 1
fi

wait