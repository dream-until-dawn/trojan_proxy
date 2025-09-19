# trojan_proxy
trojan代理docker容器

## 证书管理
### docker打包
#### 在包含 Dockerfile 和 scripts 目录的文件夹中运行：

```bash
docker build -f Dockerfile.certbot -t certbot-manager .
```
#### 运行证书管理容器
```bash
docker run -it --rm \
  --name certbot-manager \
  -v /mnt/certs:/etc/letsencrypt \
  -p 80:80 \
  -p 443:443 \
  certbot-manager
```
参数说明:
```bash
-v /path/on/host/certs:/etc/letsencrypt: 将主机上的目录挂载到容器中，用于持久化存储证书
-p 80:80 -p 443:443: 映射端口，HTTP 验证方式需要这些端口
```

#### 使用容器
运行容器后，你将看到一个交互式菜单，可以选择不同选项来管理 SSL 证书：
> 申请新证书 (HTTP 验证): 使用 HTTP-01 挑战验证域名所有权
> 申请新证书 (DNS 验证): 使用 DNS-01 挑战验证（需要提前配置 Cloudflare API）
> 续订所有证书: 检查并续订即将过期的证书
> 查看证书信息: 显示已安装证书的详细信息
> 删除证书: 移除不再需要的证书
> 设置自动续订: 配置自动续订任务
> 退出: 退出证书管理工具

#### 其他
参考自此链接脚本
```bash
https://raw.githubusercontent.com/atrandys/trojan/master/trojan_mult.sh
```