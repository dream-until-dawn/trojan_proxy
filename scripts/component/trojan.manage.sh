#!/bin/bash
source /opt/scripts/component/utils.sh

wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest >/dev/null 2>&1
TROJAN_VERSION=`grep tag_name latest| awk -F '[:,"v]' '{print $6}'`
rm -f latest
TROJAN_TARBALL="trojan-$TROJAN_VERSION-linux-amd64.tar.xz"
TROJAN_DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v$TROJAN_VERSION/$TROJAN_TARBALL"
RANDOMSTRING=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
TROJAN_INSTALLDIR="/opt"
TROJAN_INSTALLPREFIX=/usr/local
TROJAN_SYSTEMDPREFIX=/etc/systemd/system

TROJAN_BINARYPATH="$TROJAN_INSTALLPREFIX/bin/trojan"
TROJAN_SERVERCONFIGPATH="$TROJAN_INSTALLPREFIX/etc/trojan/server.json"
TROJAN_CLIENTCONFIGPATH="$TROJAN_INSTALLPREFIX/etc/trojan/client.json"

install_latest_trojan() {
    mkdir -p $RANDOMSTRING
    info "进入临时工作目录 ${RANDOMSTRING}..."
    cd "$RANDOMSTRING"
    info "开始下载 trojan ${TROJAN_VERSION}..."
    wget -q --show-progress "$TROJAN_DOWNLOADURL"
    success "下载成功开始解压 ${TROJAN_TARBALL}..."
    tar xf "${TROJAN_TARBALL}" -C "${TROJAN_INSTALLDIR}" >/dev/null 2>&1 || {
        error "解压失败,请检查文件完整性"
        exit 1
    }
    rm -f "$TROJAN_TARBALL"
    info "trojan解压完成,移除临时目录 ${RANDOMSTRING}..."
    rm -rf "$RANDOMSTRING"
    cd "${TROJAN_INSTALLDIR}/trojan"
    info "开始安装 trojan ${TROJAN_VERSION} 至 ${TROJAN_BINARYPATH}..."
    install -Dm755 "trojan" "$TROJAN_BINARYPATH"
    # 验证安装
    if command -v trojan >/dev/null 2>&1; then
        success "trojan 命令已可用，版本信息："
        trojan --version
    else
        warning "trojan 命令不在PATH中，尝试重新加载PATH"
        export PATH="$TROJAN_INSTALLPREFIX/bin:$PATH"
        trojan --version
    fi
    _password=$TROJAN_PW
    if [ -z "${_password}" ]; then
        _password=$RANDOMSTRING
        warning "未设置trojan密码,使用随机密码:${_password}"
    fi
    write_in_trojan_config "${_password}";
    
}

write_in_trojan_config(){
    mkdir -p "$(dirname "$TROJAN_SERVERCONFIGPATH")"
    cat > $TROJAN_SERVERCONFIGPATH <<-EOF
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
    cat > $TROJAN_CLIENTCONFIGPATH <<-EOF
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