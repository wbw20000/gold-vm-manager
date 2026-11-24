# 首次使用排错 · First-run troubleshooting

[返回首页](../README.md) · [English](#english)

| 现象 | 先做什么 |
| --- | --- |
| 创建报 `insufficient-safe-staging-space` | 看宿主可用空间，不是 VM 内剩余容量。默认 50 GiB，1.5.1 起也可选 30 GiB。宿主缓存和虚拟盘在同一卷时，复用已缓存的默认镜像按所选容量 +12 GiB 检查；首次下载或手工重新导入按 +32 GiB 检查。以失败卡显示的实际缺口为准。低于门槛时本次还没开始恢复系统。旧的失败暂存盘或重复导入的 IPSW 可能仍占空间；归档任务不等于删除暂存盘。不要删除仍在使用的 VM 或唯一的恢复镜像。 |
| 设置助理选完「成人」一直转圈 | 先确认本次从「首次设置启动…」进入，管理器显示「首次设置 · 普通网络，未过滤」。如果走的是受保护启动，先在客机内正常关机再检查启动方式。若已是普通网络，检查宿主联网情况；仅凭转圈无法确定原因。不要提前标记首次设置完成。 |
| Clash Verge 提示「正在从临时路径运行」 | 退出 Clash。在**客机 Finder** 中，把应用从 `gold-installers` 逐个拖到客机桌面，再从桌面逐个拖入「应用程序」。如已直接复制进「应用程序」，先移到客机桌面再移回。从「应用程序」打开，不要在共享目录中启动，也不要清除隔离属性。 |

如仍失败，报告管理器版本、宿主 macOS 版本、失败步骤和固定错误码即可。不要附真实 YAML、节点地址、账号或未脱敏的日志。

## English

| Symptom | First check |
| --- | --- |
| `insufficient-safe-staging-space` | Check **host** free space. Starting in 1.5.1 the default is 50 GiB and the minimum is 30 GiB. On the same host volume allow the selected size plus 12 GiB with a cached, default IPSW, or plus 32 GiB for a new download/explicit import. The error reports the actual shortfall; this attempt stopped before restore. Archived staging disks and repeated IPSW imports can still take up space. Archiving is not deletion. Keep your only restore image and any live VM disks. |
| Setup Assistant spins after selecting Adult | Verify the manager shows **首次设置 · 普通网络，未过滤** (First Setup · ordinary, unfiltered network). If started in protected mode, shut down normally and check the startup mode. If already on ordinary networking, check the host connection; the spinner alone does not reveal its cause. Do not mark setup complete yet. |
| Clash Verge reports it is running from a temporary path | Quit Clash. In the **guest Finder**, drag the apps individually from `gold-installers` to the guest Desktop, then from the Desktop to Applications. If already copied directly to Applications, move the app to the guest Desktop and back. Open the copy in Applications; do not remove quarantine attributes. |

For support, share the app version, host macOS version, failed step, and fixed error code—not your YAML, endpoints, account details or unredacted logs.
