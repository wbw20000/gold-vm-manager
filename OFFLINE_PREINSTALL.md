# 首次开机前：完整 GUI 应用离线预装

这是 **显式调用、仅全新暂存磁盘** 的开发接口，不是普通 VM 开机、发布或已安装宿主 GUI 的自动升级。原 `offline_validate` 只恢复系统，仍停在 `awaiting_offline_preinstall`；恢复成功和下载成功都不能标为应用已预装。

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

## 磁盘边界

[offline_disk.py](<offline_disk.py>) 的 `StageTarget.load` 只接受当前同 job/name 的 `offline_validate` 新暂存区：恢复成功、没有 source VM、未发布、未普通启动、未预装、未复制凭据。目录与关键文件必须 canonical/private/current-user-owned，镜像大小匹配原恢复请求。

[offline_volume.py](<offline_volume.py>) 分别提供只读未挂载、只读 Data 挂载、显式授权 RW 未挂载、RW Data 挂载的**不同类型**契约，不把 RW 数据改造为只读数据以求通过。校验完整 image → GUID → partition UUID → APFS physical store → container UUID → volume UUID → 唯一 System/Data group；不靠 `Data` 卷名或保存的 `/dev/diskN` 选择磁盘。

- 每次设备动作前重新核对 exact image mapping 与同一 attachment generation；身份变化只报告需人工核对，不猜测、不 detach 替代 attachment。
- plist 重复键在 decode 时直接拒绝，不能经 `plistlib.loads/dumps` 消掉重复键后冒充原始证据。
- 只允许新 Data 卷挂载；其他卷不能被顺带挂载。不会 unlock、repair、force-unmount、弱化 FileVault/SIP，或写入 System 卷。
- [offline_writable.py](<offline_writable.py>) 要求完整新 RW capture 与先前只读图中所有持久 UUID/大小/角色一致。写入期间保持镜像 inode/size，config/NVRAM 不变。
- APFS 的正常 journal/应用写入可以改变镜像 mtime。必须在成功 unmount+detach 后、仍持原生命周期锁时，重新加载 post-write signature，并核对仍是原 inode/size/config/NVRAM，才可进行新的只读会话。不能对任意替换文件盲目 rebase。

## 受限写入与成功条件

[offline_install.py](<offline_install.py>) 仅向 Data 的 `Applications` 新建四个之前不存在的应用目录。不会覆盖既有目标，不删除失败目录，不创建账号、不跳过 Setup Assistant、不安装服务、不复制宿主节点/订阅/账号、不会调用 Tart 启动。

- 调用前再次验证**全部**来源应用，检查空间、没有用户 home、没有 `.AppleSetupDone`。
- 独占创建每个目标目录，完整复制原 bundle，核对 inode、内容树和 quarantine。
- 任一失败：保留未发布暂存磁盘和失败证据，不进行破坏性自动重试。
- macOS `ditto --qtn` 默认开启，但合并到**事先独占创建的应用根目录**时不会带入该目录的 quarantine。写入器因此显式读取原应用根的实际值，只在新目标缺失时新增该属性，并逐字回读核对；已有不同属性立即拒绝，绝不清除或覆盖。
- 复制完成仍是 `applications_preinstalled=false`，必须卸载、detach、重新只读附加/挂载，再从客机磁盘独立验证四个完整 app 的版本、签名、notarization、树哈希和 quarantine，并再次干净 detach。

[offline_preinstall.py](<offline_preinstall.py>) 的显式入口为：

```python
preinstall_stage(
    state_dir=private_restore_state,
    tart_home=private_tart_stage_root,
    job_id=restore_job_id,
    name=fresh_vm_name,
    materials=tuple_of_three_reviewed_official_Material_objects,
    evidence_dir=new_private_evidence_directory,
    acknowledge_write=True,
    external_lock=production_lifecycle_lock_if_separate,
)
```

`Material` 是原始 archive acquisition receipt、固定 manifest 和该 archive 的受控提取结果；**不能传入宿主已安装应用或宿主用户配置**。完整 manifest 必须逐项等于固定 catalog。入口持生命周期/配置锁跨越全部验证、RO→RW→RO 操作；不会发布到 VM registry。

成功状态是 `awaiting_first_desktop_acceptance`，不是 legacy `awaiting_user_setup`：

```json
{
  "applications_preinstalled": true,
  "guest_started": false,
  "desktop_verified": false,
  "credentials_copied": false,
  "published": false
}
```

仅在最终只读验证和 detach 成功后写成功 receipt。状态/UI 不提供新 VM 启动按钮。中断遗留的 active 标志若已失去生命周期锁，会被显示为 interrupted + recovery_required，阻止覆盖重试。

**首次桌面运行、服务/代理实际可用、账号登录、许可/管理员授权以及产品交付仍未验收，需要另行明确授权。** 此开发变更不会自动替换已安装的宿主应用或启动另一个服务器。

## 明确审查后的非破坏性续装

[offline_recovery.py](<offline_recovery.py>) 的 `resume_verified_prefix` 是独立显式接口，需要 `acknowledge_recovery=True`、精确失败 operation ID 和原始私有失败/cleanup/copy 证据。它不是自动 retry，也不删除、重复制或覆盖已有应用字节。

1. `StageTarget.load(..., review_failed_operation_id=...)` 只产生 **readonly_review** 对象，直接交给 RW 会话会被拒绝；仍要求同一新建恢复任务、未发布、未开机、未完成用户设置。
2. 持原生命周期/配置锁，重新验证全部官方来源，再新建只读附件检查同一 Data/group UUID。既有应用必须构成固定应用集合的连续完整前缀，每个字节/权限/相对 link 都与已验证官方原件一致；未知项目、半包、损坏或修改的 bundle 一律拒绝。
3. 仅在上述只读审查及干净 detach 之后，才允许显式续装决定升级同一 inode/size 的暂存对象。再次核对既有 bundle 全树，保留其 inode/内容且不对它运行 ditto；只补确实缺失的原始 quarantine，然后独占新建剩余缺失应用。
4. 最后仍需完整四 app 的独立只读重挂验签、树与原始 quarantine 对比、最终 detach。成功状态提交之后才保存最终成功 evidence receipt；中途异常保持 failed + recovery_required。

原失败证据不覆盖；新的续装证据会指出保留了哪些完整应用。暂存 sidecar 记录物理磁盘验证，若后续状态写入失败，它不单独代表整个操作已提交；以最终状态和最终 receipt 一致为准。

## 回归测试

```sh
/usr/bin/python3 -B -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/test_offline_ui.js
```

自动化 fixtures 与真实磁盘证据分开保存；fixtures 不能冒充真实预装。私有 IPSW、VM 镜像、下载原件和真实 UUID 只放在 gitignored evidence 中，不进入源代码测试 fixtures。
