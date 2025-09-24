#!/bin/bash
source ./component/utils.sh
source ./component/acme.manage.sh

# 显示菜单函数
show_menu() {
    cd /opt/scripts
    info "====================================================="
    info "      瓜瓜的VPN Docker"
    info "      (acme使用邮箱: $EMAIL)"
    info "      (acme使用域名: $DOMAIN)"
    info "====================================================="
    info "1. 查看证书信息"
    info "2. 申请新证书 (HTTP 验证)"
    info "3. 续订证书"
    info "0. 退出脚本"
    info "====================================================="
    echo -n "请输入选项 [0-3]: "
}

# 查看证书信息
view_certs() {
    success "ssl证书:"
    if get_acme_cert; then
        bash ~/.acme.sh/acme.sh --info -d $DOMAIN
    fi
    read -p "按任意键继续..."
}

# 申请证书 (HTTP 验证)
issue_cert_http() {
    if ! check_ip; then
        read -p "按任意键继续..."
        return 1
    fi
    issue_acme_cert
    read -p "按任意键继续..."
}

# 续订证书（带确认提示）
renew_certs() {
    # 提示用户确认
    read -p "是否强制更新证书?(y/n) " confirm
    case "$confirm" in
        [yY][eE][sS]|[yY])
            renew_acme_cert
        ;;
        *)
            info -e "已取消操作。"
        ;;
    esac
    read -p "按任意键继续..."
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
                view_certs
            ;;
            2)
                issue_cert_http
            ;;
            3)
                renew_certs
            ;;
            *)
                warning "无效选项，请重新选择"
                read -p "按任意键继续..."
            ;;
        esac
    done
}

main