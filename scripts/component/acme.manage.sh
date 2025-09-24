#!/bin/bash
source /opt/scripts/component/utils.sh

ACME_OLD="/opt/scripts/fallback/acme.sh"
ACME_OLDTAR="/opt/scripts/fallback/acme.sh-master.tar.gz"
ACME_DOWNLOADURL="https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh"

install_latest_acme(){
    if ! $FORCE_LOCAL; then
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
    bash ./acme.sh --install 1>/dev/null 2>&1
    rm -rf /tmp/acme.sh-master
    success "本地安装acme.sh成功"
    cd /opt/scripts
}

# 使用脚本安装acme.sh
install_acme() {
    cd /tmp
    info "正在安装: $1"
    chmod +x "$1"
    bash "$1" email="$EMAIL" 1>/dev/null 2>&1 || {
        error "安装失败，尝试其他方法..."
        cd /opt/scripts
        return 1
    }
    cd /opt/scripts
    return 0
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
    get_acme_cert;
    ret=$?
    if [ $ret -eq 1 ]; then
        bash ~/.acme.sh/acme.sh --register-account -m $EMAIL --server zerossl
        bash ~/.acme.sh/acme.sh --issue -d $DOMAIN --nginx
        success "证书申请成功"
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
        bash ~/.acme.sh/acme.sh  --installcert -d $DOMAIN   \
        --key-file /usr/src/trojan-cert/$DOMAIN/private.key \
        --fullchain-file /usr/src/trojan-cert/$DOMAIN/fullchain.cer \
        --reloadcmd "bash /opt/scripts/restart_trojan.sh"
        success "证书保存成功"
        return 0
    else
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