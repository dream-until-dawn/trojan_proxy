#!/bin/bash
source /opt/scripts/component/utils.sh

ACME_OLD="/opt/scripts/fallback/acme.sh"
ACME_OLDTAR="/opt/scripts/fallback/acme.sh-master.tar.gz"
ACME_DOWNLOADURL="https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh"

install_latest_acme(){
    if $FORCE_LOCAL; then
        warning "强制使用本地安装acme.sh"
        install_local_acme
        return 0
    fi
    info "尝试从网络下载get.acme.sh..."
    if wget --timeout=30 -q -O /tmp/get.acme.sh "https://get.acme.sh" 1>/dev/null 2>&1; then
        success "远程下载get.acme.sh成功"
        if install_acme /tmp/get.acme.sh; then
            success "在线安装acme.sh成功"
            rm -f /tmp/get.acme.sh
            return 0
        else
            error "在线安装acme.sh失败"
            install_local_acme
            return 0
        fi
    else
        error "远程下载get.acme.sh失败"
        install_local_acme
    fi
}

install_local_acme(){
    info "开始解压本地旧版acme.sh..."
    tar xzf $ACME_OLDTAR -C /tmp
    info "开始安装本地旧版acme.sh..."
    cd /tmp/acme.sh-master
    bash ./acme.sh --install --cert-home /opt/acme-certs 1>/dev/null 2>&1
    rm -rf /tmp/acme.sh-master
    success "本地安装acme.sh成功"
    cd /opt/scripts
}

# 使用脚本安装acme.sh
install_acme() {
    cd /tmp
    info "正在安装: $1"
    chmod +x "$1"
    bash "$1" email="$EMAIL" --cert-home /opt/acme-certs 1>/dev/null 2>&1 || {
        error "安装失败，尝试其他方法..."
        cd /opt/scripts
        return 1
    }
    cd /opt/scripts
    return 0
}

# 显示菜单函数
show_acme_menu() {
    clear
    cd /opt/scripts
    info "====================================================="
    info "      管理acme.sh脚本"
    info "      (acme使用邮箱: $EMAIL)"
    info "      (acme使用域名: $DOMAIN)"
    info "====================================================="
    info "1. 查看证书信息"
    info "2. 申请新证书 (HTTP 验证)"
    info "3. 续订证书"
    info "0. 返回主菜单"
    info "====================================================="
    echo -n "请输入选项 [0-3]: "
}

while_show_acme_menu() {
    # 主循环
    while true; do
        show_acme_menu
        read choice
        case $choice in
            0)
                info "返回主菜单"
                return 0
            ;;
            1)
                # 查看证书信息
                check_cert
            ;;
            2)
                # 申请新证书 (HTTP 验证)
                issue_acme_cert
            ;;
            3)
                # 续订证书（带确认提示）
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
            ;;
            *)
                warning "无效选项，请重新选择"
            ;;
        esac
        read -p "按任意键继续..."
    done
}

# 查看证书信息
check_cert(){
    if [ ! -d "/opt/acme-certs" ] || [ -z "$(ls -A /opt/acme-certs)" ]; then
        warning "未绑定acme.sh内部域名管理目录,或未申请过证书"
        if [ -f "/usr/src/trojan-cert/$DOMAIN/fullchain.cer" ]; then
            warning "检测到域名 $DOMAIN 证书存在,但未绑定acme.sh管理"
            return 1
        fi
    else
        get_acme_cert
        case $? in
            0)
                info "证书信息:"
                bash ~/.acme.sh/acme.sh --info -d $DOMAIN
            ;;
            2)
                bash ~/.acme.sh/acme.sh --info -d $DOMAIN
            ;;
        esac
    fi
}

# 取得证书
get_acme_cert(){
    if [ ! -d "/usr/src/trojan-cert" ]; then
        mkdir -p /usr/src/trojan-cert
        mkdir -p /usr/src/trojan-cert/$DOMAIN
    fi
    if [ -f "/usr/src/trojan-cert/$DOMAIN/fullchain.cer" ]; then
        cd /usr/src/trojan-cert/$DOMAIN
        create_time=`stat -c %Y fullchain.cer`
        now_time=`date +%s`
        minus=$(($now_time - $create_time ))
        if [  $minus -gt 5184000 ]; then
            error "2)证书存在但已过期"
            return 2
        else
            warning "检测到域名 $DOMAIN 证书存在且未超过60天,无需重新申请"
            return 0
        fi
    else
        error "1)证书不存在"
        return 1
    fi
}

# 申请证书
issue_acme_cert(){
    if ! check_ip; then
        return 1
    fi
    get_acme_cert;
    ret=$?
    if [ $ret -eq 1 ]; then
        bash ~/.acme.sh/acme.sh --register-account -m $EMAIL --server zerossl
        bash ~/.acme.sh/acme.sh --issue -d $DOMAIN --nginx
        success "证书申请成功"
        bash ~/.acme.sh/acme.sh  --installcert -d $DOMAIN   \
        --key-file /usr/src/trojan-cert/$DOMAIN/private.key \
        --fullchain-file /usr/src/trojan-cert/$DOMAIN/fullchain.cer \
        --reloadcmd "bash /opt/scripts/restart_trojan.sh"
        success "证书保存成功"
        return 0
    else
        warning "证书已存在，无需申请"
        return 1
    fi
}

# 续订证书
renew_acme_cert(){
    get_acme_cert;
    ret=$?
    case $ret in
        0)
            if bash ~/.acme.sh/acme.sh --renew -d "$DOMAIN" --force; then
                success "证书续订成功！"
                return 0
            else
                error "错误：证书续订失败！"
                return 1
            fi
        ;;
        2)
            if bash ~/.acme.sh/acme.sh --renew -d "$DOMAIN" --force; then
                success "证书续订成功！"
                return 0
            else
                error "错误：证书续订失败！"
                return 1
            fi
        ;;
        *)
            return 1
        ;;
    esac
}