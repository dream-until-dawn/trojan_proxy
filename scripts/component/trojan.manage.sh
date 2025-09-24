#!/bin/bash
source /opt/scripts/component/utils.sh

mkdir -p /mnt/tmp_download
wget https://api.github.com/repos/trojan-gfw/trojan/releases/latest -P /mnt/tmp_download >/dev/null 2>&1
rm -f /mnt/tmp_download
TROJAN_VERSION=`grep tag_name /tmp_download/latest| awk -F '[:,"v]' '{print $6}'`
TROJAN_TARBALL="trojan-$TROJAN_VERSION-linux-amd64.tar.xz"
TROJAN_OLD="/opt/scripts/fallback/trojan-1.16.0-linux-amd64.tar.xz"
TROJAN_DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v$TROJAN_VERSION/$TROJAN_TARBALL"
RANDOMSTRING=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 12)
TROJAN_INSTALLDIR="/opt"
TROJAN_INSTALLPREFIX=/usr/local
TROJAN_SYSTEMDPREFIX=/etc/systemd/system

TROJAN_BINARYPATH="$TROJAN_INSTALLPREFIX/bin/trojan"
TROJAN_SERVERCONFIGPATH="$TROJAN_INSTALLPREFIX/etc/trojan/server.json"
TROJAN_CLIENTCONFIGPATH="$TROJAN_INSTALLPREFIX/etc/trojan/client.json"

CERTIFICATEPATH="/usr/src/trojan-cert/${DOMAIN}/fullchain.cer"
KEYPATH="/usr/src/trojan-cert/${DOMAIN}/private.key"

install_latest_trojan() {
    if $FORCE_LOCAL; then
        warning "强制使用本地安装trojan"
        install_trojan "$TROJAN_OLD"
        return 0
    fi
    if [ -z "$TROJAN_VERSION" ]; then
        error "未找到trojan最新版本,使用本地旧版"
        install_trojan "$TROJAN_OLD"
        return 0
    else
        info "找到trojan最新版本: $TROJAN_VERSION"
        info "开始下载 trojan ${TROJAN_VERSION}..."
        wget -q --show-progress "$TROJAN_DOWNLOADURL"
        install_trojan "$TROJAN_DOWNLOADURL"
        success "在线安装完成,删除在线下载文件"
        rm -f "$TROJAN_TARBALL"
        return 0
    fi
}

install_trojan() {
    success "开始解压 $1..."
    tar xf $1 -C "${TROJAN_INSTALLDIR}" >/dev/null 2>&1 || {
        error "解压失败,请检查文件完整性"
        exit 1
    }
    info "开始安装 trojan ${TROJAN_VERSION} 至 ${TROJAN_BINARYPATH}..."
    install -Dm755 "${TROJAN_INSTALLDIR}/trojan/trojan" "$TROJAN_BINARYPATH"
    # 验证安装
    if [ -x "$TROJAN_BINARYPATH" ]; then
        info "文件已正确安装，正在验证可执行性..."
        if "$TROJAN_BINARYPATH" --version >/dev/null 2>&1; then
            success "trojan 命令已可用"
        else
            error "文件存在但无法执行，可能是依赖问题"
            ldd "$TROJAN_BINARYPATH" || true
            exit 1
        fi
    else
        error "文件安装失败或不可执行"
        exit 1
    fi
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
        "cert": "$CERTIFICATEPATH",
        "key": "$KEYPATH",
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

# 检查trojan是否正在运行
is_trojan_running() {
    # 方法1：检查进程名和动态链接器组合
    if pgrep -f "ld-linux-x86-64.*trojan" >/dev/null || pgrep -x "trojan" >/dev/null; then
        return 0  # 正在运行
    fi
    # 方法2：检查端口占用（更可靠）
    if ss -tulnp | grep -qE ':443\b.*trojan'; then
        return 0
    fi
    return 1  # 没有运行
}


# 启动trojan
start_trojan() {
    if is_trojan_running; then
        warning "trojan 已经在运行中"
        return 1
    fi
    
    if ! check_port_conflict 443; then
        error "启动前端口检查失败"
        return 1
    fi
    
    if [ ! -f "${CERTIFICATEPATH}" ]; then
        error "证书文件不存在,请先申请证书"
        return 1
    fi
    
    if [ ! -f "${KEYPATH}" ]; then
        error "证书密钥文件不存在,请先申请证书"
        return 1
    fi
    
    _password=$TROJAN_PW
    if [ -z "${_password}" ]; then
        _password=$RANDOMSTRING
        warning "未设置trojan密码,使用随机密码:${_password}"
    fi
    write_in_trojan_config "${_password}";
    
    info "使用证书 ${CERTIFICATEPATH} 和密钥 ${KEYPATH} 启动 trojan..."
    if ! trojan -t "$TROJAN_SERVERCONFIGPATH"; then
        cat "$TROJAN_SERVERCONFIGPATH" | jq . >/dev/null 2>&1 || {
            error "trojan 配置文件格式错误"
            return 1
        }
        error "trojan 配置文件校验失败"
        return 1
    fi
    
    success "trojan 配置文件校验成功,开始启动 trojan..."
    nohup trojan -c "$TROJAN_SERVERCONFIGPATH" >/dev/null 2>&1 &
    sleep 1  # 等待进程启动
    
    if is_trojan_running; then
        success "trojan 启动成功"
        return 0
    else
        error "trojan 启动失败"
        # 修改启动部分为：
        info "尝试前台运行trojan..."
        if trojan -c "$TROJAN_SERVERCONFIGPATH"; then
            success "trojan 启动成功"
            return 0
        else
            error "trojan 启动失败，最后错误信息："
            # 获取最后一次错误
            local last_err=$(dmesg | grep trojan | tail -n 1)
            [ -n "$last_err" ] && error "$last_err"
            return 1
        fi
    fi
}

# 停止trojan
stop_trojan() {
    if ! is_trojan_running; then
        warning "trojan 已经停止"
        return 1
    fi
    
    info "正在停止 trojan..."
    fuser -k 443/tcp
    
    # 二次确认
    sleep 1
    if ! is_trojan_running; then
        success "trojan 已停止"
        return 0
    else
        error "trojan 停止失败"
        return 1
    fi
}


# 重启trojan
restart_trojan() {
    stop_trojan
    start_trojan
}

# 检查trojan状态
check_trojan_status() {
    if is_trojan_running; then
        success "trojan 正在运行"
        return 0
    else
        warning "trojan 没有运行"
        return 1
    fi
}
