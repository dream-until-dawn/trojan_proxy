# trojan_proxy(开发中)
trojan代理docker容器

## 证书管理
### docker打包
#### 在包含 Dockerfile 和 scripts 目录的文件夹中运行：

```bash
docker build -f Dockerfile.trojan -t trojan .
```
#### 运行容器
```bash
docker run -it -d \
  -p 80:80 \
  -p 443:443 \
  --name trojan \
  trojan
  -e EMAIL=test@example.com \
  -e DOMAIN=example.com \
  -v /mnt:/usr/src/trojan-cert
```
参数说明:
```bash
-v /mnt:/usr/src/trojan-cert: 将主机上的目录挂载到容器中，用于持久化存储证书
-p 80:80 -p 443:443: 映射端口，HTTP 验证方式需要这些端口
-e EMAIL=test@example.com -e DOMAIN=example.com: 设置邮箱和域名，用于申请证书
```
#### 申请证书
先进入容器
```bash
docker exec -it trojan bash
```
再开始交互
```bash
bash menu.sh
```

#### 其他
参考自此链接脚本
```bash
https://raw.githubusercontent.com/atrandys/trojan/master/trojan_mult.sh
```