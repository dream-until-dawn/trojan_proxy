# Trojan Proxy

面向个人服务器的 HTTPS 网关、独用管理后台和 Trojan 服务。**v1.0.0** 使用固定摘要 Docker 镜像，域名、证书、反代和 VPN 在后台配置。

## 第一次使用

正式支持 **Linux / amd64**，建议至少 2GiB 内存。需要 Docker Engine、Compose 插件和 SSH 权限；服务器 **80、443 必须空闲**。无域名也能先部署 HTTP，后台通过 SSH 隧道访问。

在服务器执行：

```bash
mkdir -p ~/trojan-proxy-download
cd ~/trojan-proxy-download
curl -fLO https://github.com/dream-until-dawn/trojan_proxy/releases/download/v1.0.0/trojan-proxy-v1.0.0.zip
curl -fLO https://github.com/dream-until-dawn/trojan_proxy/releases/download/v1.0.0/trojan-proxy-v1.0.0.zip.sha256
sha256sum -c trojan-proxy-v1.0.0.zip.sha256
unzip trojan-proxy-v1.0.0.zip
cd trojan-proxy-v1.0.0/deploy
mkdir -p public
docker compose up -d --pull missing
docker compose ps -a
docker compose exec control proxyctl setup-token
```

`prepare` 成功退出、三个服务运行即为正常启动。最后一条命令在交互终端显示十分钟有效的令牌，请勿分享。在自己的电脑另开终端，替换用户名和服务器 IP：

```bash
ssh -N -L 18092:127.0.0.1:18092 -L 18090:127.0.0.1:18090 用户名@服务器IP
```

打开 `http://127.0.0.1:18092`，设置至少 16 字节的强口令、绑定手机验证器并离线保存恢复码。完成后打开 `http://127.0.0.1:18090` 登录后台。**没有默认账号和密码，不要把初始化端口开放到公网。**

DNS、自动 HTTPS、后台子域名、反代和 VPN 的后续操作请按包内 **`docs/user-guide/quickstart.html`** 完成。HTML 手册可直接离线浏览；GitHub 文件预览通常显示 HTML 源码，下载发行包后打开效果完整。

## 功能

- 无域名 HTTP；有域名自动申请和管理证书，HTTP 跳转 HTTPS。
- 单管理员强口令＋TOTP、离线恢复码、近期双因素敏感操作保护。
- 按子域名、路径和自定义端口反代到宿主机回环服务；只读目录发布。
- Trojan 独立端口或共享 443、网页回落、仅回环引擎。
- Clash Verge / Clash Mi 每设备 URL 订阅、导入与更新。
- 网站请求记录：白名单 IP 保留 7 天，其他来源 30 天；白名单只分类，不拦截访问。
- 独立的 VPN 目标 IP、上下行流量和采样速率，滚动保留 30 天。

## 手册

| 内容 | HTML 文件 |
| --- | --- |
| 从下载到首次可用 | [首次部署](docs/user-guide/quickstart.html) |
| 功能、端口与支持边界 | [功能说明](docs/user-guide/features.html) |
| 每个配置项、子域名/端口/目录反代示例 | [配置手册](docs/user-guide/configuration.html) |
| 备份、升级、密码恢复与冷还原 | [维护恢复](docs/user-guide/operations.html) |
| 证书、登录、502、订阅与客户端排障 | [常见问题](docs/user-guide/troubleshooting.html) |
| 本版内容、发布证据及限制 | [v1.0.0 版本说明](docs/releases/v1.0.0.html) |
| 架构、开发计划和历史验证 | [开发文档](docs/index.html) |

正式包通过 45 项候选 CI，镜像源码与运行代码绑定；完整 24 小时、1441 条核心样本及 25 轮真实 VPN 正反向已按本项目范围验收。原整站两次外部期货上游 502 保留，**不宣称整站零失败**。

下载地址：[GitHub Releases](https://github.com/dream-until-dawn/trojan_proxy/releases)。默认清单固定镜像摘要；升级应下载目标版本清单并按手册保留数据卷。

## 注意事项

- 常驻组件为 `control`、`admin-gateway`、`vpn-runner`，`prepare` 为一次性预检。不能与其他网关争用 80/443。
- 当前仅实现 Trojan；其他 VPN 协议为扩展接口。反代上游只支持宿主回环 HTTP 服务。
- 订阅 URL、私钥、恢复码和备份都是秘密。撤销订阅不能收回已经下载的节点口令。
- 不要使用 `docker compose down -v` 停止服务，否则会删除持久卷。
- 根目录 `docker-compose.yml`、`Dockerfile.trojan` 和旧 acme.sh/nginx 脚本是历史实现，**不属于 v1.0.0 部署方式**。使用发行包 `deploy/compose.yaml`；旧版升级按全新部署迁移，先保留备份。

## 开发验证

```bash
python tools/validate.py
python -m unittest discover -s tools/stability -p 'test_*.py'
python -m unittest discover -s tools/release -p 'test_*.py'
python tools/release/check_docs.py
```

根模块和两个独立引擎均需测试，单独 `go test ./...` 会漏掉嵌套模块。完整镜像扫描、隔离 Docker 正反向和定向破坏探针由候选工作流执行。正式发行工具会拒绝运行源码漂移、缺失长稳验收和镜像摘要不匹配。

MIT License，见 [LICENSE](LICENSE)。
