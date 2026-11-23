# Gold VM Manager

**[加入 Gold VM 微信交流群](https://weixin.qq.com/g/AQYAAMoC6cPVM_wJbKwTY4TAaGCjDxIoHfW81qVt9QjcPD3nTesOm66syMumSJMb)** · 用微信扫一扫；手机上可长按识别。群邀请有有效期。

<a href="docs/media/wechat-group.png?raw=true"><img src="docs/media/wechat-group.png" width="180" alt="Gold VM 微信交流群二维码，点开放大"></a>

在 Apple Silicon Mac 上创建独立的 macOS 虚拟机，在客机里使用 Claude Code。首次设置用普通网络；完成设置后，受保护启动只允许客机通过已配置的代理节点出站，不会在代理断开时自动直连。

**[下载 v1.4.0 源码](https://github.com/wbw20000/gold-vm-manager/releases/tag/v1.4.0) · [看 23 秒安装演示](docs/media/guest-install.gif?raw=true) · [下载并填写 YAML](#下载并填写-yaml宿主-mac) · [四个应用装好后怎么用](#四个应用装好后怎么用客机) · [English](README.en.md)**

> **我的使用记录（本人确认：2026-11-21）**：我现在就在用这台虚拟机跑 Claude Code。用 Pro 的 4 天没有被封；升级 Max 后，截至这次记录，用了 2 天，也没有被封。[我的使用分享 ↗](https://x.com/clarkwang258/status/2123747367639994757)
>
> **升级 Max 起的日历计数：第 <!-- max-days:start -->4<!-- max-days:end --> 天。** 数字每天按新加坡日期更新，不登录或查询我的 Claude 账号；上面那段是我本人确认过的记录。

[![管理器实际界面：左侧选择虚拟机，右侧查看状态和操作](docs/media/manager-overview.png)](docs/media/manager-overview.png?raw=true)
*实际界面，使用演示数据。点图可放大。*

## 安装管理器（宿主 Mac）

1. **先核对：**Apple Silicon、macOS **26.6.2**（当前验证版本）、Apple Command Line Tools 或 Xcode、系统 Python 3.9+ 和 Ruby/Psych。默认 50 GiB 虚拟盘的创建门槛是 **82 GiB** 可用空间；下载或导入 IPSW 还要给镜像和缓存留空间。
2. 在 [v1.4.0 发布页](https://github.com/wbw20000/gold-vm-manager/releases/tag/v1.4.0)下载 **Source code (zip)** 并解压。双击 [Install.command](Install.command)，或在源码目录运行 `./Install.command`。完成后，从 `~/Applications` 打开 **Gold VM 管理器**。
3. 这是**本地签名的源码构建**，不是 Apple 公证的成品安装包。安装器不覆盖已有 App，也不自动开机；不要关闭 Gatekeeper。另装新版本见[源码安装指南](SOURCE_INSTALL.md)。

## 下载并填写 YAML（宿主 Mac）

1. **下载。** 在管理器点「新建 VM 及预装软件 → 下载 YAML 填写模板」，或打开 [GitHub 模板](examples/vpn/clash.yaml)，点右上角 **Download raw file（下载原始文件）**。[也可直接打开原始 YAML](https://raw.githubusercontent.com/wbw20000/gold-vm-manager/v1.4.0/examples/vpn/clash.yaml)；如果浏览器显示文本而没下载，按 `⌘S`。把文件存到仓库之外，命名为 `clash.local.yaml`，不要带 `.txt` 后缀。
2. **选协议。** 用纯文本编辑器打开文件，把 `proxies: []` 改为 `proxies:`。找到与你的节点协议一致的一组示例，只删除**那一组**每行开头的 `# `，保留剩下的空格缩进。不要把订阅链接粘进 `server`。
3. **填节点服务商给你的值。** 例如 Trojan TLS/TCP 填好后的**格式**如下。`server` 是节点公网地址，`port` 是整数端口，`password` 是节点密码，`sni` 是服务商指定的 TLS 域名；以下全是占位值，不能直接连接。VLESS、TUIC 等请填模板里对应协议的字段，不要照搬 Trojan 密码栏。

   ```yaml
   proxies:
     - type: trojan
       server: 192.0.2.10
       port: 443
       password: "REPLACE_WITH_TROJAN_PASSWORD"
       sni: vpn.example.com
       network: tcp
       skip-cert-verify: false
   ```

4. **把文件交给管理器。** 保存后，在宿主 Finder 选中文件，按 `⌥⌘C` 复制完整路径，粘贴到「本地 Clash YAML 绝对路径」。填新 VM 名称与镜像，点「校验并私有保存节点 → 同意并开始预装」。如果 `server` 是域名，需要单独允许本机解析；校验通过只代表格式有效，不代表节点已连通。[查看创建窗口](docs/media/manager-create.png?raw=true)

**节点配置存在哪里？** 填好的 YAML 不上传 GitHub；宿主私有目录和首次设置的只读共享里含有明文节点凭据，不要分享文件或 VM 磁盘。还没准备好节点，可以选「先不配置 VPN」，之后补配置再发布。

## 第一次使用：看状态，做下一步

| 看到什么 | 接下来做什么 |
| --- | --- |
| **未启动 · 待首次设置** | 点「首次设置启动…」，确认本次使用**普通网络，未经过滤**。完成 macOS 设置，进入客机桌面。 |
| **Finder → My Shared Files → gold-installers** | 先读「先读我.txt」。把四个应用从共享文件夹**逐个拖到客机桌面，再逐个拖进「应用程序」**。不要在共享中直接打开。 |
| **四个应用已在「应用程序」** | 不用把四个都打开。先配置 Clash Verge，再用 CCBaga A 自检，最后使用 Claude；具体操作如下。 |

[![Finder 安装示意：共享文件夹 → 客机桌面 → 应用程序](docs/media/guest-install.gif)](docs/media/guest-install.gif?raw=true)
*[放大循环动图](docs/media/guest-install.gif?raw=true) · [静态步骤图](docs/media/guest-install.png?raw=true)。示意动画，非客机实录。*

## 四个应用装好后怎么用（客机）

1. **先通代理：Clash Verge。** 从「应用程序」打开 Clash Verge →「订阅 → 新建 → 本地 → 选择文件」，选择 **My Shared Files → gold-installers → Clash 节点配置.yaml**。点「保存」，再点选刚建的订阅使它生效。这里选的是管理器为这台客机生成的文件，**不是 GitHub 的空模板**。
2. **开 TUN 并验证流量。** 在 Clash Verge 的「设置」开启「虚拟网卡模式（TUN）」，按客机提示安装服务。用客机浏览器打开网页，同时看 Clash 的「连接」，确认这次请求走了选定的节点，而不是 `DIRECT`。首次设置用普通网络，能打开网页本身不算通过。
3. **再做环境自检：CCBaga A。** 点「浏览器环境」检测；「电脑环境」可对齐时区，按需在客机的「隐私与安全性 → 定位服务」关闭定位，再复查。此流程用 **A**，不需要同时启动 **CCBaga B**。各项变绿后可打开 [IP/DNS 自检页](https://ip.net.coffee/claude/)，参考标准是 **≥70 分且本次未报告 IP/DNS 泄露**。这是第三方诊断，不是 Claude 的账号资格判定，不要在那里输入凭据。
4. **切到日常网络。** 确认代理正常后，在客机内正常关机。回宿主管理器点「标记首次设置完成…」→「受保护启动…」。标记不可撤销，之后不再挂安装共享。开机后再检查一次 Clash 连接记录。
5. **最后用 Claude。** 图形聊天就从客机「应用程序」打开 **Claude Desktop**；命令行开发请在**客机内**按 [Claude Code 官方指南](https://code.claude.com/docs/en/quickstart)另行安装，再在客机终端运行 `claude` 并按官方提示登录。装好 Desktop 不等于装好了 Code。

[遇到问题？空间不足 / 设置助理转圈 / Clash 提示临时路径](docs/first-run-troubleshooting.md) · [完整设置指南](ONE_CLICK_PREINSTALL.md) · [隐私与安全](SECURITY.md)
