#!/bin/bash
source ./untill.sh

NAME=trojan
VERSION=$(curl -fsSL https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name | sed -E 's/.*"v(.*)".*/\1/')
TARBALL="$NAME-$VERSION-linux-amd64.tar.xz"
DOWNLOADURL="https://github.com/trojan-gfw/$NAME/releases/download/v$VERSION/$TARBALL"
TMPDIR="$(mktemp -d)"
INSTALLPREFIX=/usr/local
SYSTEMDPREFIX=/etc/systemd/system

BINARYPATH="$INSTALLPREFIX/bin/$NAME"
SERVERCONFIGPATH="$INSTALLPREFIX/etc/$NAME/server.json"
CLIENTCONFIGPATH="$INSTALLPREFIX/etc/$NAME/client.json"

install_latest_trojan() {
    info 进入临时工作目录 $TMPDIR...
    cd "$TMPDIR"
    echo 开始下载 $NAME $VERSION...
    wget -q --show-progress "$DOWNLOADURL"
    success 下载成功开始解压 $NAME $VERSION...
    tar xf "$TARBALL"
    cd "$NAME"
    info 开始安装 $NAME $VERSION 至 $BINARYPATH...
    install -Dm755 "$NAME" "$BINARYPATH"
    success $NAME $VERSION 安装成功
    _password=$TROJAN_PW
    if [ -z "$_password" ]; then
        _password=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
        warning "未设置trojan密码,使用随机密码$_password"
    fi
    write_in_trojan_config "$_password";
    echo 完成安装脚本,移除临时目录 $TMPDIR...
    rm -rf "$TMPDIR"
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