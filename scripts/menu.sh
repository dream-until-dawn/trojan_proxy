#!/bin/bash
source ./untill.sh

# 显示菜单函数
show_menu() {
    cd /opt/scripts
    clear
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
    echo -n "请输入选项 [1-5]: "
}

# 查看证书信息
view_certs() {
    success "ssl证书:"
    bash ~/.acme.sh/acme.sh --info -d $DOMAIN
    read -p "按任意键继续..."
}

# 申请证书 (HTTP 验证)
issue_cert_http() {
    real_addr=`ping -c 1 $DOMAIN | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=$(wget -qO- http://ipv4.icanhazip.com)

    if [ $real_addr == $local_addr ]; then
        # 目录是否存在
        if [ ! -d "/usr/src" ]; then
            mkdir /usr/src
        fi
        if [ ! -d "/usr/src/trojan-cert" ]; then
            mkdir /usr/src/trojan-cert /usr/src/trojan-temp
            mkdir /usr/src/trojan-cert/$DOMAIN
            if [ ! -d "/usr/src/trojan-cert/$DOMAIN" ]; then
                error "不存在/usr/src/trojan-cert/$DOMAIN 目录"
                exit 1
            fi
            bash ~/.acme.sh/acme.sh  --register-account  -m $EMAIL --server zerossl
            bash ~/.acme.sh/acme.sh  --issue  -d $DOMAIN  --nginx
            if test -s /root/.acme.sh/$DOMAIN/fullchain.cer; then
                cert_success="1"
            fi
        elif [ -f "/usr/src/trojan-cert/$DOMAIN/fullchain.cer" ]; then
            cd /usr/src/trojan-cert/$DOMAIN
            create_time=`stat -c %Y fullchain.cer`
            now_time=`date +%s`
            minus=$(($now_time - $create_time ))
            if [  $minus -gt 5184000 ]; then
                bash ~/.acme.sh/acme.sh  --register-account  -m $EMAIL --server zerossl
                bash ~/.acme.sh/acme.sh  --issue  -d $DOMAIN  --nginx
                if test -s /root/.acme.sh/$DOMAIN/fullchain.cer; then
                    cert_success="1"
                fi
            else 
                green "检测到域名 $DOMAIN 证书存在且未超过60天,无需重新申请"
                cert_success="1"
            fi        
        else 
            mkdir /usr/src/trojan-cert/$DOMAIN
            bash ~/.acme.sh/acme.sh  --register-account  -m $EMAIL --server zerossl
            bash ~/.acme.sh/acme.sh  --issue  -d $DOMAIN  --nginx
            if test -s /root/.acme.sh/$DOMAIN/fullchain.cer; then
                cert_success="1"
            fi
        fi

        if [ "$cert_success" == "1" ]; then
            green "证书申请成功！"
            cat > /etc/nginx/conf.d/80.conf <<-EOF
server {
    listen       127.0.0.1:80;
    server_name  $DOMAIN;
    root /usr/share/nginx/html;
    index index.php index.html index.htm;
}
server {
    listen       0.0.0.0:80;
    server_name  $DOMAIN;
    return 301 https://$DOMAIN\$request_uri;
}
EOF
            bash ~/.acme.sh/acme.sh  --installcert  -d  $DOMAIN   \
            --key-file   /usr/src/trojan-cert/$DOMAIN/private.key \
            --fullchain-file  /usr/src/trojan-cert/$DOMAIN/fullchain.cer \
            --reloadcmd  "systemctl restart trojan"	
            nginx -s reload
            sleep 1  # 等待重启完成
            if pgrep nginx > /dev/null; then
                success "Nginx重启成功"
            else
                error "Nginx重启失败"
                exit 1
            fi
    else
        error "域名解析地址与本VPS IP地址不一致"
        info "域名解析地址: $real_addr"
        info "本VPS IP地址: $local_addr"
    fi
    read -p "按任意键继续..."
}

# 续订证书（带确认提示）
renew_certs() {
    # 提示用户确认
    read -p "是否强制更新证书?(y/n) " confirm
    case "$confirm" in
        [yY][eE][sS]|[yY])
            info -e "正在强制更新证书..."
            if bash ~/.acme.sh/acme.sh --renew -d "$DOMAIN" --force; then
                success -e "证书续订成功！"
            else
                error -e "错误：证书续订失败！" >&2
                return 1
            fi
            ;;
        *)
            info -e "已取消操作。"
            return 0
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