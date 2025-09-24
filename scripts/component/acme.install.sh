#!/bin/bash
source /opt/scripts/component/utils.sh

# 使用脚本安装acme.sh
install_acme() {
    info "正在安装: $1"
    chmod +x "$1"
    bash "$1" email="$EMAIL" || {
        error "安装失败，尝试其他方法..."
        return 1
    }
}

install_latest_acme(){
    info "尝试从网络下载acme.sh..."
    if wget --timeout=30 -q -O /tmp/get.acme.sh "https://get.acme.sh"; then
        success "远程下载成功"
        if install_acme /tmp/get.acme.sh; then
            success "在线安装acme.sh成功"
            rm -f /tmp/get.acme.sh
            return 0
        fi
    fi
    if [ -f "/opt/scripts/fallback/get.acme.sh" ]; then
        success "✓ 找到本地get.acme.sh文件"
        if install_acme /opt/scripts/fallback/get.acme.sh; then
            success "本地安装acme.sh成功"
            return 0
        else
            error "本地安装也失败了"
            return 1
        fi
    else
        error "错误：本地get.acme.sh文件不存在"
        info "当前目录内容:"
        ls -la /opt/scripts/fallback/ || error "无法列出/opt/scripts/"
        return 1
    fi
}
