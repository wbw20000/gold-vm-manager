# Gold VM Manager · 开发交接

这是可独立构建的源码仓库，不是虚拟机镜像或已公证安装包。**Claude 在客机运行；宿主只负责管理。** 这里不包含开发机器上的状态、节点、账号、日志、第三方二进制或测试磁盘。

## 先看哪里

| 范围 | 源码入口 |
| --- | --- |
| 前端 | [页面](<static/index.html>)、[主界面](<static/app.js>)、[预装向导](<static/preinstall.js>)、[主题样式](<static/style.css>)、[向导样式](<static/preinstall.css>) |
| 原生外壳和本机服务 | [AppKit/WKWebView](<NativeApp.swift>) → [引导](<bootstrap.py>) → [HTTP 控制器](<manager.py>)。服务在本机 loopback 上运行，需要令牌，写操作检查 Host 和 Origin。接口见 [API 契约](<API_CONTRACT.md>)。 |
| 新建、预装和续接 | [流程编排](<oneclick.py>)、[生命周期与状态](<lifecycle.py>)、[Apple 恢复助手](<CleanVMInstaller.swift>)、[离线预装](<offline_preinstall.py>)、[APFS 归属](<offline_volume.py>)、[发布保护](<preinstall_runtime.py>)。系统与应用从受审查的固定来源获取，不从开发机器复制。 |
| Clash 配置 | [公开占位模板](<examples/vpn/clash.yaml>)、[解析与策略](<vpn_config.py>)、[本地路径与私有票据](<vpn_store.py>)、[写盘与验收](<offline_vpn.py>)、[首次登录助手](<GuestVPNBootstrap.swift>)。界面默认填本地 YAML 绝对路径，也可先预装、后补 VPN。 |
| 系统授权和网络 | [授权请求及回执](<guest_ownership.py>)、[固定属主助手](<GuestOwnershipHelper.swift>)、[受保护启动](<protected_launcher.py>)、[端点过滤](<packet_policy.py>)。没有普通 NAT 回退。 |
| 构建 | [源码安装](<SOURCE_INSTALL.md>)、[双击入口](<Install.command>)、[打包清单](<install_app.py>)、[Git 排除项](<.gitignore>)。旧迁移工具和旧客机 setup 保留用于兼容，不是新版干净构建的前置条件。 |

## 从干净仓库验证

首个已审查组合是 Apple Silicon / macOS 26.6.2；恢复镜像固定为 26.6.2 / 25G83。源码构建需系统 Python 3.9+、Ruby/Psych、Apple Command Line Tools 或受选定的 Xcode SDK；Node 仅用于运行界面测试，不是成品运行时依赖。

在仓库根目录运行：

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p 'test_*.py'
node --test tests/test_offline_ui.js tests/test_preinstall_ui.js
```

测试使用自有临时 fixture；原生恢复助手测试会从当前源码构建，不依赖私有构建产物。上述测试不会安装或启动虚拟机。构建本地 App 时，先按 [源码安装说明](<SOURCE_INSTALL.md>)选择不存在的输出路径；不要直接覆盖当前正在运行的版本。构建后的本地签名不等于 Developer ID 公证。

## 继续开发的优先问题

1. **为宿主管理员授权失败提供可区分的、脱敏的诊断。** 已有一次真实运行完成 macOS 恢复及四个原版应用的独立只读验收；VPN 阶段失败在 `authorized-ownership-apply`。操作者未看到 macOS 管理员弹窗；没有 `apply.started` 或成功回执，暂存最后已正常卸载，未发布、未开机。不能由这些证据判断是授权请求未进入 GUI 会话，还是助手在写入前拒绝了校验。[授权桥](<guest_ownership.py>)目前丢弃 `osascript` 输出，[工作流](<offline_vpn.py>)保留步骤、但不对外返回底层原因。建议先用 fixture 分别验证启动失败、标准授权取消和助手校验失败的脱敏状态，再在有权限的前台 macOS 会话做真实验证。只记录固定错误类别，不保存管理员凭据、原生错误全文、节点或真实路径。
2. **非破坏性恢复和首次启动仍未验收。** 已经进入私有配置写盘后失败的任务，与主动选择「先不配置 VPN」的干净等待状态不同。不能把失败任务直接改成可续接，不能重新使用旧授权票据、跳过只读验收、覆盖现有盘或把未验证状态标成成功。无真实授权和获准的配置不得执行实机连通测试。固定 gvproxy 不等于受系统信任；此前静态执行评估拒绝，不能清隔离或降低 Gatekeeper 检查。
3. **验收分级。** 区分软件和磁盘核验、属主核验、事务发布、首次桌面、导入自报、VPN 连通分别成功的状态。独立 fixture、主机打包成功或客机回执不代表真 VM 网络已验收。

公开任务请使用合成样例和最小错误类别。不要把本机 `evidence/`、管理器状态、原始凭据或已填入真实节点的配置加入 Git。更多边界见 [安全说明](<SECURITY.md>)、[一键预装指南](<ONE_CLICK_PREINSTALL.md>) 和 [属主授权契约](<GUEST_OWNERSHIP.md>)。
