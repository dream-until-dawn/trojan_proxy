#!/bin/bash
# 初始化脚本 - 设置 Cloudflare API 凭据等

echo "设置 Cloudflare DNS 验证凭据..."
mkdir -p /root/.secrets
echo "dns_cloudflare_email = YOUR_CF_EMAIL" > /root/.secrets/cloudflare.ini
echo "dns_cloudflare_api_key = YOUR_CF_API_KEY" >> /root/.secrets/cloudflare.ini
chmod 600 /root/.secrets/cloudflare.ini

echo "初始化完成!"