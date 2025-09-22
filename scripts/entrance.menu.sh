#!/bin/bash
source ./untill.sh

# 显示菜单函数
show_menu() {
    clear
    info "================================="
    info "        瓜瓜的VPN Docker          "
    info "================================="
    info "1. 查看证书信息"
    info "2. 申请新证书 (HTTP 验证)"
    info "3. 续订所有证书"
    info "4. 删除证书"
    info "5. 设置自动续订"
    info "================================="
    echo -n "请输入选项 [1-5]: "
}

# 申请证书 (HTTP 验证)
issue_cert_http() {
    echo -n "请输入域名: "
    read domain
    echo -n "请输入邮箱 (用于紧急通知): "
    read email
    
    certbot certonly --standalone -d $domain --agree-tos -m $email --non-interactive
    echo -e "${GREEN}证书申请完成!${NC}"
    read -p "按回车键继续..."
}

# 续订证书
renew_certs() {
    certbot renew
    echo -e "${GREEN}证书续订完成!${NC}"
    read -p "按回车键继续..."
}

# 查看证书信息
view_certs() {
    echo -e "${GREEN}可用的证书:${NC}"
    ls /etc/letsencrypt/live/ | grep -v README
    
    echo -n "输入要查看的域名 (直接回车查看所有): "
    read domain
    
    if [ -z "$domain" ]; then
        certbot certificates
    else
        certbot certificates --cert-name $domain
    fi
    
    read -p "按回车键继续..."
}

# 删除证书
delete_cert() {
    echo -n "请输入要删除的证书域名: "
    read domain
    
    certbot delete --cert-name $domain
    echo -e "${GREEN}证书删除完成!${NC}"
    read -p "按回车键继续..."
}

# 设置自动续订
setup_auto_renew() {
    echo -e "${YELLOW}设置自动续订任务...${NC}"
    
    # 创建续订脚本
    cat > /etc/periodic/daily/certbot-renew << EOF
#!/bin/sh
certbot renew --quiet --post-hook "echo '证书续订完成'"
EOF
    
    chmod +x /etc/periodic/daily/certbot-renew
    
    # 启动 cron 服务
    crond
    
    echo -e "${GREEN}自动续订已设置! 证书将每天检查并自动续订${NC}"
    read -p "按回车键继续..."
}

main() {
    # 主循环
    while true; do
        show_menu
        read choice
        case $choice in
            1)
                issue_cert_http
                ;;
            2)
                issue_cert_dns
                ;;
            3)
                renew_certs
                ;;
            4)
                view_certs
                ;;
            5)
                delete_cert
                ;;
            6)
                setup_auto_renew
                ;;
            *)
                warning "${RED}无效选项，请重新选择${NC}"
                read -p "按回车键继续..."
                ;;
        esac
    done
}

