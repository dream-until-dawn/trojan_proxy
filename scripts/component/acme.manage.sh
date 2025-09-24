#!/bin/bash
source /opt/scripts/component/utils.sh

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
        --reloadcmd "nginx -s reload"
        success "证书保存成功,请重新启动nginx"
        return 0
    else
        return 1
    fi
}

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