#!/bin/bash
source /opt/scripts/component/utils.sh

# 显示菜单函数
show_nginx_menu() {
    clear
    cd /opt/scripts
    NGINX_STATUS="未启动"
    if is_nginx_running; then
        NGINX_STATUS="正在运行"
    fi
    info "====================================================="
    info "      管理nginx"
    info "      (nginx运行状态: ${NGINX_STATUS}"
    info "====================================================="
    info "1. 查看nginx配置"
    info "2. 启动nginx"
    info "3. 停止nginx"
    info "4. 重启nginx(仅重新加载配置文件)"
    info "5. 重启nginx"
    info "0. 返回主菜单"
    info "====================================================="
    echo -n "请输入选项 [0-5]: "
}

while_show_nginx_menu() {
    # 主循环
    while true; do
        show_nginx_menu
        read choice
        case $choice in
            0)
                info "返回主菜单"
                return 0
            ;;
            1)
                # 查看nginx配置
                success "nginx主配置:"
                cat /etc/nginx/nginx.conf
                success "nginx80端口配置:"
                cat /etc/nginx/conf.d/80.conf
            ;;
            2)
                # 启动nginx
                start_nginx
            ;;
            3)
                # 停止nginx
                stop_nginx
            ;;
            4)
                # 重启nginx(仅重新加载配置文件)
                reload_nginx
            ;;
            5)
                # 重启nginx
                restart_nginx
            ;;
            *)
                warning "无效选项，请重新选择"
            ;;
        esac
        read -p "按任意键继续..."
    done
}

# 写入 Nginx 配置文件
write_in_nginx_config(){
    cat > /etc/nginx/conf.d/80.conf <<-EOF
server {
    listen       127.0.0.1:80;
    server_name  $DOMAIN;
    root /usr/share/nginx/html;
    index index.php index.html index.htm;

    location /test {
        access_log off;
        return 200 'OK';
        add_header Content-Type text/plain;
    }
}
server {
    listen       0.0.0.0:80;
    server_name  $DOMAIN;
    return 301 https://$DOMAIN\$request_uri;
}
EOF
    success "Nginx 配置文件写入成功"
}

# 检查nginx是否正在运行
is_nginx_running(){
    if [ -f "/var/run/nginx.pid" ] && kill -0 $(cat /var/run/nginx.pid) 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

# 启动 Nginx
start_nginx(){
    info "启动nginx..."
    if is_nginx_running; then
        warning "Nginx 已经在运行"
    else
        write_in_nginx_config
        nginx -g "daemon off;" & # 启动 Nginx
        # 等待 Nginx 启动完成
        sleep 2
        # 检查 Nginx 是否启动成功
        if is_nginx_running; then
            success "Nginx 启动成功"
        else
            error "Nginx 启动失败"
        fi
    fi
}

# 停止 Nginx
stop_nginx(){
    info "停止nginx..."
    # 先检查 Nginx 是否在运行
    if ! is_nginx_running; then
        warning "Nginx 已经停止"
        return 0
    fi
    # 尝试正常停止
    if [ -f "/var/run/nginx.pid" ]; then
        nginx -s stop
        sleep 2
    fi
    # 检查是否停止成功
    if ! is_nginx_running; then
        success "Nginx 停止成功"
        return 0
    fi
    # 如果正常停止失败，使用 kill 方式
    warning "Nginx 正常停止失败，尝试强制停止..."
    # 获取所有 nginx 进程
    local nginx_pids
    nginx_pids=$(pgrep -f "nginx" | tr '\n' ' ')
    
    if [ -n "$nginx_pids" ]; then
        warning "找到 Nginx 进程: $nginx_pids"
        # 先尝试优雅终止
        kill -TERM $nginx_pids 2>/dev/null
        sleep 3
        # 检查是否停止
        if ! is_nginx_running; then
            success "Nginx 停止成功"
            return 0
        fi
        # 强制杀死
        warning "尝试强制停止..."
        kill -9 $nginx_pids 2>/dev/null
        sleep 2
        # 最终检查
        if ! is_nginx_running; then
            success "Nginx 强制停止成功"
        else
            error "Nginx 停止失败，请手动检查"
            return 1
        fi
    else
        warning "未找到 Nginx 进程，可能已停止"
    fi
}



# 重启 Nginx
restart_nginx(){
    info "重启nginx..."
    if ! is_nginx_running; then
        warning "Nginx 未在运行，尝试启动"
        start_nginx
    else
        stop_nginx
        sleep 2
        start_nginx
    fi
}

# 检查 Nginx 配置
check_nginx_config(){
    info "检查nginx配置..."
    if nginx -t > /dev/null 2>&1; then
        success "Nginx 配置正确"
    else
        error "Nginx 配置错误"
    fi
}

# 重新加载 Nginx 配置
reload_nginx(){
    info "重新加载nginx配置..."
    if ! is_nginx_running; then
        warning "Nginx 未在运行，请先启动"
        elif nginx -s reload > /dev/null 2>&1; then
        success "Nginx 配置已重新加载"
    else
        error "重新加载 Nginx 配置失败"
    fi
}
