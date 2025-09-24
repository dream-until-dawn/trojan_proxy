#!/bin/bash
EMAIL="test@${DOMAIN}"

function info(){
    echo -e "\033[34m\033[01mℹ️ $1\033[0m"
}
function success(){
    echo -e "\033[32m\033[01m✅ $1\033[0m"
}
function error(){
    echo -e "\033[31m\033[01m❌ $1\033[0m"
}
function warning(){
    echo -e "\033[33m\033[01m⚠️ $1\033[0m"
}

function check_ip(){
    real_addr=`ping -c 1 $DOMAIN | sed '1{s/[^(]*(//;s/).*//;q}'`
    local_addr=$(wget -qO- http://ipv4.icanhazip.com)
    if [ $real_addr != $local_addr ]; then
        error "域名解析地址与本VPS IP地址不一致"
        info "域名解析地址: $real_addr"
        info "本VPS IP地址: $local_addr"
        return 1
    fi
    return 0
}

# 端口冲突检查函数
# 用法: check_port_conflict <端口号>
# 返回: 0-端口可用, 1-端口被占用, 2-参数错误
check_port_conflict() {
    local port="$1"
    
    # 参数校验
    [[ "$port" =~ ^[0-9]+$ ]] || { error "端口必须是数字"; return 2; }
    (( port >= 1 && port <= 65535 )) || { error "端口范围无效"; return 2; }
    
    # 使用 ss 检查
    if ss -tulnp 2>/dev/null | awk -v p=":$port " '$5 ~ p {exit 1}'; then
        success "${port}端口可用"
        return 0
    else
        error "${port}端口被占用"
        return 1
    fi
}


