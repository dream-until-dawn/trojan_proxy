#!/bin/bash
source ./component/utils.sh
source ./component/acme.manage.sh
source ./component/nginx.manage.sh
source ./component/trojan.manage.sh

# 显示菜单函数
show_menu() {
    clear
    cd /opt/scripts
    info "====================================================="
    info "      瓜瓜的VPN Docker"
    info "====================================================="
    info "1. acme菜单(域名证书)"
    info "2. nginx菜单"
    info "3. trojan菜单"
    info "0. 退出脚本"
    info "====================================================="
    echo -n "请输入选项 [0-3]: "
}

main() {
    # 主循环
    while true; do
        show_menu
        read choice
        case $choice in
            0)
                info "退出脚本"
                exit 0
            ;;
            1)
                # acme菜单(域名证书)
                while_show_acme_menu
            ;;
            2)
                # nginx菜单
                while_show_nginx_menu
            ;;
            3)
                # trojan菜单
                while_show_trojan_menu
            ;;
            *)
                warning "无效选项，请重新选择"
            ;;
        esac
    done
}

main