#!/bin/bash
source /opt/scripts/component/utils.sh

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

# 启动 Nginx
start_nginx(){
    info "启动nginx..."
    if pgrep nginx > /dev/null; then
        warning "Nginx 已经在运行"
    else
        write_in_nginx_config
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
stop_nginx(){
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
restart_nginx(){
    info "重启nginx..."
    if ! pgrep nginx > /dev/null; then
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
    if ! pgrep nginx > /dev/null; then
        warning "Nginx 未在运行，请先启动"
        elif nginx -s reload > /dev/null 2>&1; then
        success "Nginx 配置已重新加载"
    else
        error "重新加载 Nginx 配置失败"
    fi
}
