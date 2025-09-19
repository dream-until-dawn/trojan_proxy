#!/bin/bash

# 设置默认密码（建议通过环境变量覆盖）
DEFAULT_PASSWORD=${TROJAN_PASSWORD:-"YourSecurePasswordHere"}
CONFIG_FILE="/etc/trojan/config.json"

# 检查运行模式
if [[ -f "/etc/trojan/ssl/fullchain.pem" && -f "/etc/trojan/ssl/privkey.pem" ]]; then
    echo "检测到已挂载SSL证书，使用有域名模式..."
    # 检查证书有效性（可选）
    if ! openssl x509 -checkend 86400 -noout -in /etc/trojan/ssl/fullchain.pem; then
        echo "警告：证书将在一天内过期或无效，请及时更新。"
    fi
else
    echo "未检测到SSL证书，使用无域名模式（自签名证书）..."
    # 生成自签名证书
    openssl req -newkey rsa:2048 -nodes -keyout /etc/trojan/ssl/privkey.pem \
        -x509 -days 365 -out /etc/trojan/ssl/fullchain.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=example.com"
fi

# 更新配置文件中的密码
sed -i "s/\"YOUR_PASSWORD_HERE\"/\"${DEFAULT_PASSWORD}\"/g" $CONFIG_FILE

# 显示配置信息
echo "==================== Trojan 服务器配置 ===================="
echo "运行类型: $(grep -oP '(?<="run_type": ")[^"]*' $CONFIG_FILE)"
echo "监听地址: $(grep -oP '(?<="local_addr": ")[^"]*' $CONFIG_FILE)"
echo "监听端口: $(grep -oP '(?<="local_port": )\d+' $CONFIG_FILE)"
echo "密码: ${DEFAULT_PASSWORD}"
echo "SSL证书: /etc/trojan/ssl/fullchain.pem"
echo "SSL私钥: /etc/trojan/ssl/privkey.pem"
echo "=========================================================="

# 启动Trojan
exec /usr/local/bin/trojan "$CONFIG_FILE"