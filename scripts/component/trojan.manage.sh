#!/bin/bash
source /opt/scripts/component/utils.sh

TROJAN_VERSION=""
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
    wget -q --server-response -O /tmp/tmp_download/latest https://api.github.com/repos/trojan-gfw/trojan/releases/latest 2>&1 | grep -q "HTTP/.* 200"
    if [ $? -eq 0 ]; then
        TROJAN_VERSION=$(grep tag_name /tmp/tmp_download/latest | awk -F '[:,"v]' '{print $6}')
        TROJAN_TARBALL="trojan-$TROJAN_VERSION-linux-amd64.tar.xz"
        TROJAN_DOWNLOADURL="https://github.com/trojan-gfw/trojan/releases/download/v$TROJAN_VERSION/$TROJAN_TARBALL"
        success "获取最新trojan版本成功 ${TROJAN_VERSION}"
    else
        error "trojan版本请求失败,HTTP 状态码非 200"
    fi
    
    if [ -z "$TROJAN_VERSION" ]; then
        error "未找到trojan最新版本,使用本地旧版"
        install_trojan "$TROJAN_OLD"
        return 0
    else
        cd /tmp/tmp_download
        info "找到trojan最新版本: $TROJAN_VERSION"
        info "开始下载 trojan ${TROJAN_VERSION}..."
        wget "$TROJAN_DOWNLOADURL" >/dev/null 2>&1 || {
            error "trojan下载失败,请检查网络"
            exit 1
        }
        install_trojan "$TROJAN_TARBALL"
        success "在线安装完成,删除在线下载文件"
        rm -rf /tmp/tmp_download
        cd /opt/scripts
        return 0
    fi
}

install_trojan() {
    info "开始解压 $1..."
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

# 显示菜单函数
show_trojan_menu() {
    clear
    cd /opt/scripts
    TROJAN_STATUS="未启动"
    if is_trojan_running; then
        TROJAN_STATUS="正在运行"
    fi
    info "====================================================="
    info "      管理trojan"
    info "      (trojan运行状态: ${TROJAN_STATUS}"
    info "====================================================="
    info "1. 查看trojan配置"
    info "2. 启动trojan"
    info "3. 停止trojan"
    info "4. 重启trojan"
    info "0. 返回主菜单"
    info "====================================================="
    echo -n "请输入选项 [0-5]: "
}

while_show_trojan_menu() {
    # 主循环
    while true; do
        show_trojan_menu
        read choice
        case $choice in
            0)
                info "返回主菜单"
                return 0
            ;;
            1)
                # 查看trojan配置
                success "trojan服务端配置:"
                cat $TROJAN_SERVERCONFIGPATH
                success "trojan客户端配置:"
                cat $TROJAN_CLIENTCONFIGPATH
            ;;
            2)
                # 启动trojan
                start_trojan
            ;;
            3)
                # 停止trojan
                stop_trojan
            ;;
            4)
                # 重启trojan
                restart_trojan
            ;;
            *)
                warning "无效选项，请重新选择"
            ;;
        esac
        read -p "按任意键继续..."
    done
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
    if ! trojan -t "$TROJAN_SERVERCONFIGPATH" >/dev/null 2>&1 ; then
        cat "$TROJAN_SERVERCONFIGPATH" | jq . >/dev/null 2>&1 || {
            error "trojan 配置文件格式错误"
            return 1
        }
        error "trojan 配置文件校验失败"
        return 1
    fi
    
    info "trojan 配置文件校验成功,开始启动 trojan..."
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
