#!/bin/bash
source ./component/utils.sh
source ./component/acme.manage.sh
source ./component/trojan.manage.sh
source ./component/nginx.manage.sh

set -euo pipefail

info "域名:${DOMAIN},邮箱:${EMAIL},trojan密码:${TROJAN_PW}"
info "开始安装必要程序..."
install_latest_acme
install_latest_trojan

# 启动nginx
write_in_nginx_config
start_nginx

if start_trojan;then
    restart_nginx
else
    case $? in
        3)
            info "可能是首次启动,需要申请证书文件"
            issue_acme_cert # 申请证书
            
            write_in_nginx_config_two
            restart_nginx
            
            start_trojan
        ;;
        *)
            error "trojan启动失败,或需手动执行"
        ;;
    esac
fi

exec tail -f /dev/null