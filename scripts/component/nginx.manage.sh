#!/bin/bash
source /opt/scripts/component/utils.sh

# 启动 Nginx
nginx_start(){
    info "启动nginx..."
    if pgrep nginx > /dev/null; then
        warning "Nginx 已经在运行"
    else
        nginx -g "daemon off;" & # 启动 Nginx
        # 等待 Nginx 启动完成
        sleep 2
        # 检查 Nginx 是否启动成功
        if pgrep nginx > /dev/null; then
            success "Nginx 启动成功"
        else
            error "Nginx 启动失败"
        fi
    fi
}

# 停止 Nginx
nginx_stop(){
    info "停止nginx..."
    if ! pgrep nginx > /dev/null; then
        warning "Nginx 已经停止"
    else
        nginx -s stop
        # 等待 Nginx 停止完成
        sleep 2
        # 检查 Nginx 是否停止成功
        if ! pgrep nginx > /dev/null; then
            success "Nginx 停止成功"
        else
            error "Nginx 停止失败"
        fi
    fi
}

# 重启 Nginx
nginx_restart(){
    info "重启nginx..."
    if ! pgrep nginx > /dev/null; then
        warning "Nginx 未在运行，尝试启动"
        nginx_start
    else
        nginx_stop
        sleep 2
        nginx_start
    fi
}

# 检查 Nginx 配置
nginx_check_config(){
    info "检查nginx配置..."
    if nginx -t > /dev/null 2>&1; then
        success "Nginx 配置正确"
    else
        error "Nginx 配置错误"
    fi
}

# 重新加载 Nginx 配置
nginx_reload(){
    info "重新加载nginx配置..."
    if ! pgrep nginx > /dev/null; then
        warning "Nginx 未在运行，请先启动"
    elif nginx -s reload > /dev/null 2>&1; then
        success "Nginx 配置已重新加载"
    else
        error "重新加载 Nginx 配置失败"
    fi
}
