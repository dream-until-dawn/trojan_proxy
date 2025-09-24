#!/bin/bash
source ./utils.sh

wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
VERSION=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
rm -f latest
TARBALL="trojan-$VERSION-linux-amd64.tar.xz"
DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v$VERSION/$TARBALL"
RANDOMSTRING=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
INSTALLPREFIX=/usr/local
SYSTEMDPREFIX=/etc/systemd/system

BINARYPATH="$INSTALLPREFIX/bin/trojan"
SERVERCONFIGPATH="$INSTALLPREFIX/etc/trojan/server.json"
CLIENTCONFIGPATH="$INSTALLPREFIX/etc/trojan/client.json"

install_latest_trojan() {
    mkdir -p $RANDOMSTRING
    info "进入临时工作目录 ${RANDOMSTRING}..."
    cd "$RANDOMSTRING"
    info "开始下载 trojan ${VERSION}..."
    wget -q --show-progress "$DOWNLOADURL"
    success "下载成功开始解压 trojan ${VERSION}..."
    tar xf "$TARBALL"
    rm -f "$TARBALL"
    cd "trojan"
    info "开始安装 trojan ${VERSION} 至 ${BINARYPATH}..."
    install -Dm755 "trojan" "$BINARYPATH"
    success "trojan ${VERSION} 安装成功"
    _password=$TROJAN_PW
    if [ -z "$_password" ]; then
        _password=$RANDOMSTRING
        warning "未设置trojan密码,使用随机密码:${_password}"
    fi
    write_in_trojan_config "$_password";
    info 完成安装脚本,移除临时目录 $RANDOMSTRING...
    rm -rf "$RANDOMSTRING"
}

write_in_trojan_config(){
    cat > $SERVERCONFIGPATH <<-EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "$1"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/usr/src/trojan-cert/$DOMAIN/fullchain.cer",
        "key": "/usr/src/trojan-cert/$DOMAIN/private.key",
        "key_password": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF
    success "trojan配置(服务端)文件写入成功"
    cat > $SERVERCONFIGPATH <<-EOF
{
    "run_type": "client",
    "local_addr": "127.0.0.1",
    "local_port": 1080,
    "remote_addr": "$DOMAIN",
    "remote_port": 443,
    "password": [
        "$1"
    ],
    "log_level": 1,
    "ssl": {
        "verify": true,
        "verify_hostname": true,
        "cert": "",
        "cipher_tls13":"TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "sni": "",
        "alpn": [
            "h2",
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "curves": ""
    },
    "tcp": {
        "no_delay": true,
        "keep_alive": true,
        "fast_open": false,
        "fast_open_qlen": 20
    }
}
EOF
    success "trojan配置(客户端)文件写入成功"
}