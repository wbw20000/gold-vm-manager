# Gold VM Manager

Claude code 防封分享
https://x.com/clarkwang258/status/2123747367639994757?a=N5rdDh7ujMJGPXSOWh4&s=20

简体中文 · [English](README.en.md)

在 Apple Silicon Mac 上创建独立的 macOS VM，在客机里使用 **Claude Code**。项目的目的是减少宿主与客机配置混用、代理断开后意外直连等风险，**不能保证不封号，也不能改变 Claude 的地区、账户或套餐资格**。

## 1. 安装管理器（宿主 Mac）

- **要求：**Apple Silicon、macOS **26.6.2**（目前仅验证此版本）、Apple Command Line Tools 或 Xcode、系统 Python 3.9+ 和 Ruby/Psych。
- 在 GitHub 点 **Code → Download ZIP**，解压后双击 [Install.command](Install.command)，或在源码目录运行 `./Install.command`。构建完成后，从 `~/Applications` 打开 **Gold VM 管理器**。
- GitHub 不提供现成安装包。安装器不会覆盖旧版或启动 VM；如需另装一份，见[源码安装指南](SOURCE_INSTALL.md)。

## 2. 新建 VM（宿主管理器）

1. 点 **新建 VM 及预装软件**，填写新名称，保留默认的已审核 Apple 镜像，或选择同一版本的本地 IPSW。默认 50 GiB 虚拟磁盘要求宿主至少有 **82 GiB** 可用空间，下载或导入镜像还要额外空间。
2. 将 [Clash YAML 空模板](examples/vpn/clash.yaml)复制到仓库之外，填入自己有权使用的节点。在管理器填写本机路径，点 **校验并私有保存节点 → 同意并开始预装**。别把真实 YAML、VPS 地址或凭据提交 GitHub。
3. 等待 **未启动 · 待首次设置**。宿主准备系统和安装材料，不会自动开机，也不会代你登录或授权。

## 3. 首次设置（客机）

1. 在管理器点 **首次设置启动…**，确认这次用**普通网络（未过滤）**。完成 macOS 设置并进入桌面。
2. 在客机 Finder 打开 **My Shared Files → gold-installers**，先读共享里的 **「先读我.txt」**。四个应用要**逐个拖到客机桌面，再逐个拖进「应用程序」**，不要直接从共享打开。
3. 从「应用程序」打开 **Clash Verge**，通过 **订阅 → 新建 → 本地** 导入共享里的配置，再开启 **虚拟网卡模式（TUN）**。如有管理员提示，在客机内亲自确认。检查 Clash 的连接记录，确认流量确实经过节点；网页能打开不等于代理已连通。
4. 需要 Claude Code 时，在客机内按[官方文档](https://code.claude.com/docs/en/quickstart)安装和登录。共享里的 **Claude Desktop** 不等于 Claude Code。

## 4. 以后使用受保护启动

确认 Clash 连通后，在客机内**正常关机**，再在管理器点 **标记首次设置完成… → 受保护启动…**。此后不再挂载安装共享，出站流量按规则过滤；后端或代理失败时不会退回普通网络。首次设置完成的标记不可撤销。

[详细步骤与排错](ONE_CLICK_PREINSTALL.md) · [网络与凭据安全](SECURITY.md) · [开发交接](DEVELOPMENT_HANDOFF.md)
