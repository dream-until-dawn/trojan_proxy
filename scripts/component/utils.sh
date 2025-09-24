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
