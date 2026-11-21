# Gold VM Manager

在 Apple Silicon Mac 上创建独立的 macOS 虚拟机，在客机里使用 Claude Code。首次设置用普通网络；完成设置后，受保护启动只允许客机通过已配置的代理节点出站，不会在代理断开时自动直连。

**[下载 v1.4.0 源码](https://github.com/wbw20000/gold-vm-manager/releases/tag/v1.4.0) · [看 23 秒安装演示](docs/media/guest-install.gif?raw=true) · [节点配置存在哪里？](#节点配置存在哪里) · [English](README.en.md)**

> **我的使用记录（本人确认：2026-11-21）**：我现在就在用这台虚拟机跑 Claude Code。用 Pro 的 4 天没有被封；升级 Max 后，截至这次记录，用了 2 天，也没有被封。[我的使用分享 ↗](https://x.com/clarkwang258/status/2123747367639994757)
>
> **升级 Max 起的日历计数：第 <!-- max-days:start -->2<!-- max-days:end --> 天。** 数字每天按新加坡日期更新，不登录或查询我的 Claude 账号；上面那段是我本人确认过的记录。

[![管理器实际界面：左侧选择虚拟机，右侧查看状态和操作](docs/media/manager-overview.png)](docs/media/manager-overview.png?raw=true)
*实际界面，使用演示数据。点图可放大。*

## 安装管理器（宿主 Mac）

1. **先核对：**Apple Silicon、macOS **26.6.2**（当前验证版本）、Apple Command Line Tools 或 Xcode、系统 Python 3.9+ 和 Ruby/Psych。默认 50 GiB 虚拟盘的创建门槛是 **82 GiB** 可用空间；下载或导入 IPSW 还要给镜像和缓存留空间。
2. 在 [v1.4.0 发布页](https://github.com/wbw20000/gold-vm-manager/releases/tag/v1.4.0)下载 **Source code (zip)** 并解压。双击 [Install.command](Install.command)，或在源码目录运行 `./Install.command`。完成后，从 `~/Applications` 打开 **Gold VM 管理器**。
3. 这是**本地签名的源码构建**，不是 Apple 公证的成品安装包。安装器不覆盖已有 App，也不自动开机；不要关闭 Gatekeeper。另装新版本见[源码安装指南](SOURCE_INSTALL.md)。

## 节点配置存在哪里？

- **可以不先提供节点。** 点「新建 VM 及预装软件」，填新名称并选择已审核镜像。想先试用可选「先不配置 VPN」：先恢复系统、准备软件，之后再补配置并发布。[查看创建窗口](docs/media/manager-create.png?raw=true)
- **有配置再填写。** 将 [Clash YAML 空模板](examples/vpn/clash.yaml)另存到仓库外并填好，在管理器选择本地路径，点「校验并私有保存节点 → 同意并开始预装」。管理器不把 YAML 上传 GitHub。节点凭据会以**明文**保存在宿主私有目录，首次设置时通过只读共享给客机；**只读不是加密**。不要分享填好的文件或 VM 磁盘。

## 第一次使用：看状态，做下一步

| 看到什么 | 接下来做什么 |
| --- | --- |
| **未启动 · 待首次设置** | 点「首次设置启动…」，确认本次使用**普通网络，未经过滤**。完成 macOS 设置，进入客机桌面。 |
| **Finder → My Shared Files → gold-installers** | 先读「先读我.txt」。把四个应用从共享文件夹**逐个拖到客机桌面，再逐个拖进「应用程序」**。不要在共享中直接打开。 |
| **四个应用已在「应用程序」** | 打开 Clash Verge：「订阅 → 新建 → 本地」导入共享里的配置，选中订阅，开启 TUN。在**客机里**亲自确认服务授权；宿主创建 VM 不需要这一步。 |
| **Clash 连接记录显示流量在走节点** | 正常关机 → 在管理器点「标记首次设置完成…」→「受保护启动…」。标记不可撤销。下次不再挂安装共享；不要只凭网页能打开就标记完成。 |

[![Finder 安装示意：共享文件夹 → 客机桌面 → 应用程序](docs/media/guest-install.gif)](docs/media/guest-install.gif?raw=true)
*[放大循环动图](docs/media/guest-install.gif?raw=true) · [静态步骤图](docs/media/guest-install.png?raw=true)。示意动画，非客机实录。*

共享里的是 **Claude Desktop**；要用 **Claude Code**，请在客机内按[官方指南](https://code.claude.com/docs/en/quickstart)另行安装和登录。

[遇到问题？空间不足 / 设置助理转圈 / Clash 提示临时路径](docs/first-run-troubleshooting.md) · [完整设置指南](ONE_CLICK_PREINSTALL.md) · [隐私与安全](SECURITY.md)
