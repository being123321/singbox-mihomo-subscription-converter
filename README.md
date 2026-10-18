# Subscription Forge · 订阅工坊

自建订阅转换网站：将节点链接、Base64、Clash YAML、sing-box JSON 转换为远程订阅，并生成二维码。

## 一键安装

支持 **Debian 12/13、Ubuntu 22.04/24.04，systemd**。需要 root、能访问 GitHub 的网络，以及未被其他服务占用的网站端口。安装器使用独立的 Python 服务和 Nginx；已有 Docker/Nginx Proxy Manager 的机器请使用下方手动反代方式，避免端口冲突。

```bash
curl -fsSL https://raw.githubusercontent.com/being123321/subscription-forge/main/install.sh -o install.sh && sudo bash install.sh
```

交互选择三种证书模式：

| 选项 | 用途 |
| --- | --- |
| `auto` | 自动申请 Let's Encrypt 证书并启用续期；域名须解析到服务器，80/443 可从公网访问 |
| `custom` | 使用已有证书及私钥；需提供完整证书链和私钥的绝对路径，自行续期 |
| `off` | HTTP，不使用网站证书；可使用 IPv4 或域名及自定义端口 |

自动证书示例（运行表示接受 Let's Encrypt 服务条款）：

```bash
sudo bash install.sh --host sub.example.com --tls auto --email admin@example.com
```

使用自己的证书：

```bash
sudo bash install.sh --host sub.example.com --tls custom \
  --cert /etc/ssl/sub/fullchain.pem --key /etc/ssl/sub/privkey.pem
```

HTTP 示例：

```bash
sudo bash install.sh --host 203.0.113.10 --tls off --port 8080
```

HTTP 传输不加密，节点凭据和订阅内容可能被沿途读取，部分客户端也会限制明文订阅。推荐公网使用 HTTPS。**网站证书模式与网页中的“跳过节点证书验证”是两个独立设置**；节点验证默认开启。

仅检查参数，不改动系统：

```bash
bash install.sh --host sub.example.com --tls auto --email admin@example.com --dry-run
```

## 功能

- 一个订阅链接按 User-Agent 返回 sing-box JSON、Clash Meta/Mihomo YAML 或 Base64 节点列表。
- 支持 v2rayN、v2rayNG、Shadowrocket（小火箭）节点订阅；UA 无法识别时默认节点列表。
- 可用 `?target=singbox`、`?target=clash`、`?target=xray` 显式指定格式；提供 sing-box 专用导入二维码。
- 手机 TUN；电脑可选 TUN 或本地混合代理。
- ACL4SSR 分流、腾讯域名/IP 优先直连和国内 DNS。
- 217heidai 去广告规则；一个开关控制连接及 DNS，策略组提供直连、代理、拦截。
- 自动刷新规则，每 8 小时更新，下载失败保留旧文件并重试。
- 输入最多 5 个订阅 URL、4 MB、1000 个节点；最多保存 1000 条订阅。
- 不兼容 sing-box 的 XHTTP 节点会明确省略，Clash/节点列表根据协议支持保留。

节点列表订阅不能携带完整的 DNS、TUN 或分流策略，需要对应客户端自行配置。sing-box 的“故障转移”使用 URLTest 健康选择，Mihomo 使用优先顺序 fallback，两者行为不同。腾讯直连覆盖上游规则中的地址，不保证包含全部动态游戏 IP。

## 使用

打开安装完成后显示的地址，无需访问口令。选择输入和输出格式，生成链接，复制进客户端订阅或扫描二维码。修改生成选项需要重新生成链接；服务更新会在客户端下次更新原链接时生效。使用规则模式才能执行直连分流。

本版本配置曾通过 sing-box **1.14.3、1.15.0-alpha.12** 和 Mihomo **1.19.32** 校验；这是测试基线，不是对上游最新版的承诺。游戏延迟和手机性能需在实际设备上验证。

## 手动安装 / 已有反向代理

```bash
git clone https://github.com/being123321/subscription-forge.git
cd subscription-forge
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
PUBLIC_URL=https://sub.example.com BIND=127.0.0.1 PORT=9088 DATA_DIR=./data .venv/bin/python app.py
```

将现有反向代理指向 `127.0.0.1:9088`，或同一 Docker 网络中应用可达的地址。保持 `PUBLIC_URL` 与浏览器访问地址完全一致，否则来源检查会拒绝请求。给 `/api/` 添加限速、限制请求体为 4 MB，关闭包含订阅路径的访问日志；建议上游超时至少 180 秒。

可选环境变量 `SINGBOX_BIN`、`MIHOMO_BIN`、`SINGBOX_NEXT_BIN` 指向本机可信内核，开启生成配置后的内核校验。一键安装不下载代理内核，不设置这些变量时执行转换但不额外调用外部内核校验。

## 更新与运维

重新运行安装命令即可更新源码，保留数据库与规则。更新前一版源码保存在 `/opt/subscription-forge/previous`；更新前请另行备份数据。重复安装需传入原域名和证书选项。

```bash
systemctl status subscription-forge
journalctl -u subscription-forge -n 50
curl -f http://127.0.0.1:19088/health
```

- 程序：`/opt/subscription-forge`
- 环境：`/etc/subscription-forge.env`
- 数据：`/var/lib/subscription-forge`
- Nginx：`/etc/nginx/sites-available/subscription-forge`

订阅数据库保存输入链接或节点，配置缓存也含节点凭据；它们通过文件权限保护，**未加密存储**。随机链接相当于读取凭证，请保密。服务没有账户、订阅列表或身份权限；任何人均可转换，知道订阅标识者也可撤销该订阅，不适合作为隔离的多租户平台。应用不记录代理流量或浏览历史，不代理客户端的上网流量。

旧缓存目前不会自动清理；撤销链接只删除数据库记录，旧缓存仍保留。备份或删除数据时需同时考虑缓存。HTTPS 只加密传输，不加密服务器文件。

## 开发与测试

```bash
python -m unittest discover -v
bash -n install.sh
```

`test_app.py` 覆盖公开规则 URL（包含 Tencent-DNS）、腾讯直连优先级、去广告关闭时国内 DNS 的保留。GitHub Actions 执行单元测试与安装脚本语法检查。

## 开源与上游

本仓库程序以 MIT 许可证发布，见 [LICENSE](LICENSE)。不包含私人订阅、节点凭据、服务器证书或运行时数据。

规则运行时从以下项目下载，规则及其衍生文件仍遵守各上游许可证，不因本程序 MIT 许可证改变：

- [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)：基础分流。
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)：腾讯域名和 IP。
- [217heidai/adblockfilters](https://github.com/217heidai/adblockfilters)：去广告二进制规则，GPL-3.0。

感谢上述规则维护者。本项目不附带它们的规则数据库或代理内核；再分发下载的规则前请阅读上游完整声明。
