#!/bin/bash
source ./component/untill.sh
source ./component/install.acme.sh
source ./component/nginx.manage.sh

set -e  # 遇到错误立即退出

info "开始安装acme.sh...邮箱地址: ${EMAIL}"

if start_acme; then
    info "acme.sh安装成功"
else
    error "acme.sh安装失败"
    exit 1
fi

nginx_start

wait