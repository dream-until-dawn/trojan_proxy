# trojan_proxy

trojan 代理 docker 容器

## 证书管理

### 概述

#### docker 启动时脚本流程

- 启动 docker 容器时，执行`install.environment.sh`脚本。
- 安装 acme.sh 脚本和 trojan 程序。
- 启动 nginx,使用 acme.sh 申请证书。
- 检查是否已有或未完成申请,如有使用 acme.sh 内置 80 端口服务申请证书
- 如未有,先尝试 zerossl,再尝试 letsencrypt
- 申请成功后,将证书和密钥文件保存到`/usr/src/trojan-cert`目录下
- 使用 trojan 密码和证书文件启动启动 trojan 程序

#### PS

- 非常强烈建议挂载 /usr/src/trojan-cert 和 /root/.acme.sh 目录持久化
- 有挂载目录情况下,首次启动证书申请不成功(这时仅尝试了 zerossl 和 letsencrypt),二次启动的申请会使用 standalone 方式
- 第二次启动还是失败,可以尝试自己手动申请证书,并将证书和密钥文件的本地路径挂载到 /usr/src/trojan-cert 目录下(目标目录下应有一个以你的域名为明的文件夹,在其中包含.key 和.cer 文件)
- 可以配置使用自己的前端项目作为伪装(于 Dockerfile.trojan 中修改)
  ```bash
  # 复制html
  COPY config/index.html /usr/share/nginx/html/index.html
  ```

### docker 打包

#### 在包含 Dockerfile 和 scripts 目录的文件夹中运行：

```bash
docker build -f Dockerfile.trojan -t trojan:latest .
```

### 运行容器

```bash
docker run --name trojan -it -d \
-p 80:80 -p 443:443 \
-e DOMAIN=example.com \
-e FORCE_LOCAL=false \
-e TROJAN_PW= \
-v /mnt/trojan-cert:/usr/src/trojan-cert \
-v /mnt/acme-home:/root/.acme.sh \
trojan:latest
```

参数说明:

```bash
-p 80:80 -p 443:443 ,映射端口
-e DOMAIN=example.com ,设置服务器绑定域名
-e FORCE_LOCAL=false ,acme.sh和trojan是否使用本地旧版文件安装(默认false-联网拉取最新版)
-e TROJAN_PW= ,设置trojan密码(默认为空-将使用随机密码,需留意日志输出的随机密码)
-v /mnt/trojan-cert:/usr/src/trojan-cert ,用于持久化存储证书.最好映射到本地目录
-v /mnt/acme-home:/root/.acme.sh ,因acme.sh有内部管理文件.最好映射到本地目录
```

### 容器内部操作

先进入容器

```bash
docker exec -it trojan bash
```

再开始交互

```bash
bash menu.sh
```
