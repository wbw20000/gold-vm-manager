# 首次开机前：恢复系统和准备应用

新建 VM 只恢复全新 macOS，**不再往客机磁盘写任何东西**（2026-11-20 起）。4 个应用经过下面的来源审查和提取校验后，复制进这台 VM 专用的只读安装文件夹，首次设置时由你在客机里用 Finder 安装。原 `offline_validate`（高级选项 → 仅安装 VM）只恢复系统，仍停在 `awaiting_offline_preinstall`。

为什么不再离线写盘：从宿主复制进客机 `/Applications` 的应用保留了下载隔离标记，却从没被 Finder 移动过，macOS 会把它们放到随机的只读 App Translocation 路径里运行。Clash Verge 2.5.10 启动时检查到这一点就退出。处理办法只能是用户用 Finder 移动应用，所以干脆让用户在客机里安装。

## 固定应用与来源审查

[guest_app_pins.py](<guest_app_pins.py>) 固定本次审查版本、完整 bundle、公开下载地址、SHA256、TeamID、plist 版本与关键组件：

| 产品 | 完整应用 | 版本 / TeamID |
|---|---|---|
| CCBaga 0.2.50 | CCBaga-A.app **和** CCBaga-B.app | A 0.2.50；B Chromium 148.0.7778.215 / build 7778.215；`6UB6WM6VQR` |
| Clash Verge Rev | Clash Verge.app GUI，含自身可执行文件和内置核心 | 2.5.10；`JPH3Z7PPBB` |
| Claude Desktop | Claude.app，含 Electron Framework 和 app.asar | 6.6395.0；`Q6L2SF6YDW` |

- CCBaga/Clash 原始 DMG 的 SHA256 来自各项目的 [GitHub 官方发布 API](https://api.github.com/repos/liseami/CCBaga/releases/latest)、[Clash 官方发布 API](https://api.github.com/repos/clash-verge-rev/clash-verge-rev/releases/latest)。版本 URL 与完整摘要同时固定，不自动信任下一版。
- Claude 使用 [官方发布 feed](https://downloads.claude.ai/releases/darwin/universal/RELEASES.json) 的精确官方 ZIP URL。该 feed **没有官方 SHA256**；采用同版本 [Homebrew cask 的独立二级摘要](https://raw.githubusercontent.com/Homebrew/homebrew-cask/master/Casks/c/claude.rb)，不冒充厂商摘要。
- 首次 signer bootstrap 必须先核对这些来源/摘要，再验证 Apple Developer ID 链和 notarization，最后明确固定身份；不是随便从二进制读个 TeamID 就信任。Claude 还先独立通过 Apple certificate `subject.O = "Anthropic PBC"` 约束。
- [guest_app_artifacts.py](<guest_app_artifacts.py>) 验证完整应用集合、plist、arm64、全部树哈希、`codesign --deep --strict -R '=anchor ...'` 与 `spctl` 的 `Notarized Developer ID`。不运行应用。
- [quarantine_policy.py](<quarantine_policy.py>) 使用 macOS 原生 `xattr` 保留已有 quarantine，缺失时只新增。没有删除属性、重签名或安全绕过。Apple Python 3.9 没有 Linux-only 的 `os.getxattr/setxattr`。

## 材料提取

[offline_payload.py](<offline_payload.py>) 只接受与 acquisition receipt 匹配、整包 SHA256 已核对的缓存文件。

- DMG 只读挂载在新的私有路径，不自动接受 SLA。固定原始文件身份和 attachment generation（完整 device 集合、整盘、owner、access、hdid PID），不得接管后来重新附加的同路径镜像。
- ZIP 在任何提取前检查完整 entry 与隐式父目录的 Unicode/casefold 命名空间、symlink 目标、路径边界、文件类型、大小、local header、一致性和 CRC。
- ZIP 使用**同一 Python parser**提取，不将 central-directory 验证结果转交另一个可能解释不同的原生解压器；未被目录引用的 local entries 不会被解释。
- 所有常规文件/目录写完后才创建相对内部 symlink，保留文件权限，随后再次核对原始 archive 摘要。AppleDouble 需要另一份明确支持的恢复契约：当前发现即拒绝，不能静默丢弃资源叉。此次 Claude ZIP 没有 AppleDouble。
- 提取本身仍不等于完成签名审核，更不等于写入客机。

## 首次设置用的安装文件夹

[oneclick.py](<oneclick.py>) 的 `build_installers(target, materials, private_config)` 在系统恢复之后、发布之前运行：

- 先用 [preinstall_materials.verify_materials](<preinstall_materials.py>) 把全部来源应用再完整校验一遍（签名、公证、quarantine、树哈希），不沿用之前的结果。
- 在新的目标目录里，用 APFS `clonefile` 克隆每个完整 bundle（字节、权限、内部链接和扩展属性一起，包括下载隔离标记）；只有文件系统不支持克隆时才用 `/usr/bin/ditto`。每份副本的树哈希必须等于刚校验过的原件，隔离标记必须一致，否则停止（`installer-copy-mismatch`、`installer-quarantine-mismatch`）。
- 写入 `Clash 节点配置.yaml`：校验过的私有配置原样输出为 JSON（JSON 也是合法的 YAML），节点名保留可读文字。写入 `先读我.txt`：用 Finder 安装、在 Clash Verge 导入本地订阅、打开虚拟网卡模式、确认连通、关机后标记首次设置完成。
- 文件 0644、文件夹最后改成 0755，让客机用户不论 UID 都能读；它放在 0700 的运行环境里，宿主上仍是私有的。
- 随后 [preinstall_runtime.prepare_environment](<preinstall_runtime.py>) 把整个文件夹改名移进新的 v3 运行环境，并记录它的 device/inode。受保护启动器只在首次设置期间把它以 `gold-installers` 只读挂给客机。

失败时保留暂存盘和已建的部分文件夹，不自动重试；任务可以归档后用新名称重新预装。

## 回归测试

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/test_offline_ui.js tests/test_preinstall_ui.js
```

自动化 fixtures 与真实磁盘证据分开保存；fixtures 不能冒充真实预装。私有 IPSW、VM 镜像、下载原件和真实 UUID 只放在 gitignored evidence 中，不进入源代码测试 fixtures。
