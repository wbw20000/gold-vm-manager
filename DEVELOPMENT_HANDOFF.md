# Gold VM Manager · 开发交接

这是可独立构建的源码仓库，不是虚拟机镜像或已公证安装包。**Claude 在客机运行；宿主只负责管理。** 这里不包含开发机器上的状态、节点、账号、日志、第三方二进制或测试磁盘。

## 最新变化（2026-11-20）：不再写客机磁盘

负责人决定简化流程。新建 VM 只恢复全新 macOS；4 个应用和节点配置放进一个只读安装文件夹，首次设置时挂给客机，由用户用 Finder 安装、在 Clash Verge 里导入。离线写盘、文件归属授权（root 助手和管理员弹窗）、首次登录导入程序都已删除。详见下文「不再写客机磁盘（追加）」。下面 2026-11-18 起的记录保留作历史，其中关于离线写盘和属主授权的内容已经过时。

2026-11-23 起（1.5.3）：新建的 VM 默认和宿主共享剪贴板，见下文「宿主与客机共享剪贴板（追加）」。

## 当前状态（2026-11-18，历史）

- **实机进度**：有一次真实运行完成了 macOS 恢复和四个原版应用的独立只读验收，随后在 VPN 阶段的 `authorized-ownership-apply` 失败。操作者没看到管理员弹窗；没有 `apply.started` 或成功回执；暂存盘已正常卸载，未发布、未开机。之后重跑又失败，界面只显示「请查看失败步骤」，却没有列出任何步骤。
- **本轮已完成**：
  - 让这类失败能看出「哪一步、什么原因」（A）。
  - 修复审查中确认的三项缺陷：共享目录黑名单过窄（B1）、`status.pending` 残留导致 VM 无法启动（C1）、失败任务无法解锁（C2）。
  - 详见下文「本轮改动」。
- **宿主复核**：在已审查的 Apple Silicon / macOS 26.6.2 宿主，861 项 Python 测试和 37 项界面测试均通过。诊断版 App 已构建到新路径，原生外壳和辅助程序通过本地签名核验。尚未用诊断版跑真实预装或系统授权。
- **下一步的关键输入**：新版界面在下一次失败时显示的代码。拿到代码后，按下文「按失败代码决定下一步」选择修复方向。

## 先看哪里

| 范围 | 源码入口 |
| --- | --- |
| 前端 | [页面](<static/index.html>)、[主界面](<static/app.js>)、[预装向导](<static/preinstall.js>)、[主题样式](<static/style.css>)、[向导样式](<static/preinstall.css>) |
| 原生外壳和本机服务 | [AppKit/WKWebView](<NativeApp.swift>) → [引导](<bootstrap.py>) → [HTTP 控制器](<manager.py>)。服务在本机 loopback 上运行，需要令牌，写操作检查 Host 和 Origin。接口见 [API 契约](<API_CONTRACT.md>)。 |
| 新建、预装和续接 | [流程编排和安装文件夹](<oneclick.py>)、[生命周期与状态](<lifecycle.py>)、[Apple 恢复助手](<CleanVMInstaller.swift>)、[应用材料](<preinstall_materials.py>)、[发布保护](<preinstall_runtime.py>)。系统与应用从受审查的固定来源获取，不从开发机器复制，也不写进客机磁盘。 |
| Clash 配置 | [公开占位模板](<examples/vpn/clash.yaml>)、[解析与策略](<vpn_config.py>)、[本地路径与私有票据](<vpn_store.py>)。校验后的配置写进安装文件夹的「Clash 节点配置.yaml」，由用户在客机里导入。界面默认填本地 YAML 绝对路径，也可先恢复系统、后补 VPN。 |
| 网络 | [受保护启动](<protected_launcher.py>)、[端点过滤](<packet_policy.py>)。首次设置用普通网络；标记完成后没有普通 NAT 回退。 |
| 失败代码 | [异常到公开代码的映射](<error_codes.py>)。界面只显示固定代码，不显示原生输出、路径或节点数据。 |
| 构建 | [源码安装](<SOURCE_INSTALL.md>)、[双击入口](<Install.command>)、[打包清单](<install_app.py>)、[Git 排除项](<.gitignore>)。旧迁移工具和旧客机 setup 保留用于兼容，不是新版干净构建的前置条件。 |

## 本轮改动（2026-11-18）

改动范围：`error_codes.py`（新增）、`guest_ownership.py`、`offline_vpn.py`、`oneclick.py`、`manager.py`、`runtime_shares.py`、`protected_launcher.py`、`install_app.py`、`static/app.js`、`API_CONTRACT.md`，以及对应测试（新增 `tests/test_protected_launcher.py`）。没有改动 Swift 代码。

### A. 预装失败可诊断

失败信息沿以下链路传到界面：

1. [`request_authorization`](<guest_ownership.py:624>) 读取 osascript 的 stderr，只用正则从最后一行取出末尾的状态号，归入固定类别，然后立即丢弃原文。结果存入 [`AuthorizationResult`](<guest_ownership.py:73>) 的两个字段：`failure_reason` 和 `failure_status`。
   - 授权前的本地校验（票据、helper 摘要、签名）失败时，直接返回 `preflight-rejected`，**不会调用 osascript**。
   - 启动失败返回 `launch-failed`，超时返回 `timeout`。
2. [`_authorization_code`](<offline_vpn.py:392>) 把结果拼成 `system-authorization-<reason>[-<status>]`。
3. VPN 工作流的失败分支把内部步骤和原因写进两处：`build-current.json` 的 `vpn_configuration.failed_step / failure_code`，以及 `vpn-failed.json`。
4. [`_worker_failure`](<oneclick.py:740>) 先用 [`error_codes.public_code`](<error_codes.py:46>) 求出外层代码，再把内层的步骤和原因转成任务字段 `failed_step / failure_reason`。
5. [`PREINSTALL_PHASE_FIELDS`](<manager.py:40>) 把这两个字段透出给 `/api/state`。
6. [`renderBuildJob`](<static/app.js:794>) 在失败卡片上显示三行：「失败步骤 / 原因 / 代码」。

`public_code` 按以下顺序取值，都不满足时用调用方给的默认码：

1. 异常的 `.code` 属性；
2. 本项目定义的 `ValueError` 子类中，`args[0]` 符合带连字符 slug 格式的值；
3. 按异常类名查表 `_CLASS_CODES`；
4. 内置异常（例如 `RuntimeError('任意文本')`）一律不采用其文本。

**有意的行为变化**：VPN 阶段失败时，`failure_code` 从通用的 `preinstall-step-failed` 改为 `offline-vpn-failed-retained`；VPN 配置读取失败改为 `vpn-configuration-unavailable`。依赖旧代码的脚本需要同步修改。

### 按失败代码决定下一步

界面「代码」一行的格式是 `failure_code / failure_reason`，下表按 `failure_reason` 列出。

| `failure_reason` | 含义 | 建议下一步 |
| --- | --- | --- |
| `system-authorization-preflight-rejected` | 本地校验未通过，**从未弹窗** | 核对 helper 构建产物与票据 metadata 的摘要、权限和本地签名（`_identity`、`host_tools.verify_local_signature`）。 |
| `system-authorization-launch-failed` | 无法启动 `/usr/bin/osascript` | 检查控制器进程的运行环境。 |
| `system-authorization-interaction-not-allowed` | 系统不允许当前进程弹出交互窗口（-60007） | 在已登录的前台桌面会话里打开管理器。长期方案是由原生 App 发起授权，与下文 B2 一起做。 |
| `system-authorization-user-cancelled` / `-authorization-denied` | 弹窗出现过，但被取消或密码错误。现在任务会先暂停、等你选择重试（见下文「授权被拒后原地重试」）；只有放弃、超时或第 3 次仍被拒才会以这个代码失败 | 弹窗标题显示为「osascript」，容易被忽略。改由原生 App 发起。 |
| `system-authorization-helper-exit-2` | 旧助手的通用失败，或新版未分类错误 | 不反推成具体原因。对已终止的任务不要重放票据、改阶段或覆盖回执。 |
| `system-authorization-helper-exit-20` 至 `-32` | 新助手的固定失败类别；结合 `failed_step` 区分写入/复核 | 见[属主助手诊断表](<GUEST_OWNERSHIP.md#native-failure-categories>)。同一编号只定位检查类别，不证明可以安全重试。 |
| `system-authorization-helper-exit-126` / `-127` | shell 无法执行 helper | 检查 helper 的路径、权限和所在卷。 |
| `system-authorization-helper-exit-N`（N≥128） | helper 被信号终止 | — |
| `system-authorization-authorization-error-N` | 其他系统授权错误 | 按错误号查 Security 框架的状态码。 |
| `system-authorization-timeout` | 30 分钟内没有完成 | — |
| `system-authorization-unknown-failure` | stderr 无法解析 | 在宿主终端手动跑一次 osascript，确认 stderr 格式与 `_classify_osascript_failure` 的预期一致。 |
| `guest-ownership-validation-failed` 或其他回执代码 | helper 退出码为 0，但回执校验未通过 | 对照 [属主授权契约](<GUEST_OWNERSHIP.md>) 核对回执。 |
| `internal-error` | 内部步骤抛出了非项目异常 | 根据 `failed_step` 定位到该步骤再排查。 |

### B1. 共享目录黑名单（[runtime_shares.py](<runtime_shares.py>)）

- **改动**：新增拒绝以下目录：
  - 整个 `~/Library`；
  - 家目录下的所有隐藏目录；
  - `~/Applications/tart.app`；
  - 中文名的已安装 App。
- **例外**：`~/Library/Mobile Documents` 和 `~/Library/CloudStorage` 下面的项目子目录仍可共享，但这两个根目录本身不行。
- **原因**：读写共享 `~/Library/LaunchAgents` 等目录，会让客机能在宿主上执行代码。
- **未做**：没有改成「只允许指定项目根」的白名单，目前仍是黑名单。

### C1. 状态文件（[protected_launcher.py](<protected_launcher.py>)）

- `write_status` 改用 `mkstemp` 生成唯一的临时文件名，失败时会删除临时文件。
- 拿到 `run.lock` 后，会清理旧版残留的固定名 `status.pending`。只有当它是本用户的普通文件、且没有其他硬链接时才删除；否则拒绝启动。
- **已发布的 VM 用的是创建时复制的旧启动器**，这项修复只对新发布的环境生效。

### C2. 归档失败任务

- 失败卡片新增「归档此失败任务（保留暂存盘）」按钮，需要输入完整 VM 名称确认。
- 后端：[`oneclick.archive_failed`](<oneclick.py:846>)，接口 `POST /api/preinstall/archive`，请求体恰好是 `{job_id, confirm_name}`。
- 归档的动作是：持有 `build.lock`，把 `build-current.json` 移到 `build-jobs/<id>/archived-current.json`，之后就能用新名称重新预装。
- 拒绝归档的情况：
  - 任务仍在进行，或正在等待配置 VPN；
  - 已发布，或存在 `commit.json`；
  - 内层操作仍在进行；
  - 暂存盘仍挂载；
  - 名称或 id 不符；
  - 有其他操作正在运行。

  有其他操作正在运行时返回 409 `busy`；其余情况统一返回 409 `archive_rejected`，提示文字是固定的，不回显内部原因。
- **暂存盘不会被删除、续接或发布**，仍在 `~/.tart/.gold-manager-staging/<id>/`，会继续占用磁盘，需要人工核对后再处理。

### 授权被拒后原地重试（追加）

- **起因**：实测时取消了管理员弹窗，任务直接失败，只能归档后从头预装。
- **做法**：取消、密码错误或系统不允许弹窗时，root 助手并没有运行。工作流不再直接失败，而是保持同一个已挂载的会话和两把锁，停下来等你选择（[`_authorize`](<offline_vpn.py>)）。
  - 卡片显示原因和两个按钮：「重新请求管理员授权」「放弃（保留现场）」。放弃需要确认。
  - 接口 `POST /api/preinstall/authorization`，请求体恰好是 `{job_id, attempt, decision}`。后端写一个私有、一次性的决定文件，由正在等待的进程读取后删除。
  - 选择重试后，先重新核对挂载和所有暂存身份，再用同一张票据请求授权。
  - 最多请求 3 次，每次最多等 15 分钟。放弃、超时或第 3 次仍被拒时，按原来的失败流程处理，失败代码保持原始原因。
- **安全依据**：
  - 只有票据目录里**没有** `<操作>.started` 和回执时才允许重试。helper 在任何改动前都会写这个一次性标记，并拒绝已有标记的票据，所以即使判断有误，helper 也会自己拒绝。
  - 等待期间磁盘保持挂载，和现在等待授权弹窗时（最长 30 分钟）的状态一样。
  - 任务阶段保持 `awaiting_system_authorization`，操作仍是 active，正好满足 helper 对任务状态的检查，所以**没有改 Swift**。
- **不重试的情况**：超时（osascript 被强杀后 helper 可能仍在运行）、helper 退出码、原因未知、授权前的本地校验失败。
- **已知限制**：
  - 已经失败的任务仍然只能归档。
  - 如果在等待期间关机或进程被杀，任务会变成「中断」，并且内层操作仍标为 active，归档会拒绝。这与以前在授权过程中崩溃的情况相同，需要人工核对。

### 材料下载：复用缓存、失败原因、进度（追加）

- **起因**：一次预装在下载 CCBaga 时失败（约 101 MiB 时中断），界面只显示 `downloading-failed`，看不出是超时还是连接中断，还显示着过时的 IPSW 提示；本机已有完整的应用缓存，却仍要重新下载。
- **复用缓存**：[`MaterialManager.load_reusable`](<preinstall_materials.py>) 只从本存储里挑选与当前固定版本一致、已完成且没有失败记录的下载，最多试最新的 3 个，每个都经 `load()` 做完整的原生重新校验；不通过就跳过，原样保留，不修复。全部不通过时 [`oneclick`](<oneclick.py>) 照常重新下载。任务记录 `materials_source`（`reused` / `downloaded`），卡片会显示。
- **失败原因**：[`error_codes.network_failure_code`](<error_codes.py>) 把网络异常归入固定类别（`download-timeout`、`download-connection-lost`、`download-connect-failed`、`download-dns-failed`、`download-tls-failed`、`download-network-unreachable`、`download-protocol-error`、`host-disk-full`），应用下载和系统镜像下载都使用。材料层不再把下载层的代码改写成 `<阶段>-failed`，并记录失败的项目（`failed_product`）。卡片显示失败项目、中文原因和代码。
- **进度**：应用下载新增字节进度（约每 2% 一次），卡片显示「正在下载 CCBaga（101/318 MiB）」以及解包、校验阶段，不再停留在 IPSW 提示。
- **没做**：自动续传 / 自动重试。下载层已有带固定哈希校验的 `resume_artifact`，但项目原则是不自动重试，需要负责人决定后再接。
- **注意**：宿主上有一个未提交的 stash（「Preserve unfinished retained-disk retry…」），它修改了 `preinstall_materials.py` 和 `host_artifacts.py`。本次改动避开了它触及的位置，但恢复 stash 时仍需检查。

### 写入属主改到启用所有权的挂载上（追加）

- **起因**：实测 bb1 两次管理员授权都通过，复核属主时助手退出码 2。写入属主那步是在「忽略所有权」（owners off）的挂载上做的，而 macOS 在这种挂载上会悄悄丢弃改属主操作（`fchown` 返回成功、磁盘上不变），复核时读到的还是旧属主。这是根据 xnu 行为的推断，没有在 root 下实测确认（负责人决定直接修）。
- **做法**（只改 Python，[offline_vpn.py](<offline_vpn.py>)）：写配置仍用 owners off 的可写挂载（新证据目录 `seed-write-session`，因为宿主用户要写进 root 所有的客机目录）；写完卸载，再以 owners **on** 重新可写挂载到原来的 `write-session`（助手要求的固定路径），在这里收集并哈希文件、生成票据、请求 root 改属主。之后的只读核对和复核不变。
- **新增检查**：重新挂载后收集到的文件必须与刚写入的完全一致（inode、权限、大小、哈希），否则在弹出授权前就失败，代码 `seed-changed-before-ownership-apply`，失败步骤 `owners-on-reattach`（界面显示「以启用所有权方式重新挂载」）。Python 仍不在 owners on 的挂载上读取私有配置做快照。
- **客机实测的前提**：在同版本 macOS（26.6.2 / 25G83）的客机上，用普通用户在 owners off 下创建的文件，换成 owners on 挂载后仍显示为该用户所有并可读，所以宿主用户能在 owners on 的挂载上收集文件。
- **后续宿主实测（独立空白 APFS，不是 VM）**：以真实管理员身份在 owners-off、owners-on 两种挂载上改属主。前者调用成功但只读重挂后不保留，后者确实保留。另一个差异是：owners-off 上由普通用户创建的文件在 owners-on 重挂后，普通进程看到自身身份，而 root 看见 `99:99`。这能复现写入前旧数值比较的误拒，不能追溯断言旧任务的通用退出码只可能是这一个原因。
- **修复**：票据 v2 加入每项的 ctime；授权助手仅在写入前区分锁持有进程的凭据视图和真实属主，不把 99 当通配符。在执行修改前仍须精确匹配第一次 root 校验时的真实身份，并在修改后以及独立只读重挂时按最终目标数字严格核验。老票据不迁移、不重放，失败盘保留。详见 [GUEST_OWNERSHIP.md](<GUEST_OWNERSHIP.md>)。

### 网络后端换成 Red Hat 签名并公证的 gvproxy（追加）

- **起因**：bb1 发布后无法开机。宿主内核日志显示 macOS 拒绝执行它的 gvproxy：固定的官方发布文件只有临时签名、没有公证，带隔离属性时一定被拒；私有副本也不见了。曾提议「下载时不加隔离属性」，宿主会话认为这是绕开 macOS 的判断，拒绝执行，该方案已撤回。
- **做法**：改从 Podman 6.2.0 官方 macOS 安装包取 gvproxy。
  - 安装包固定 SHA-256，下载后照常加隔离属性；核对 Red Hat（HYSCB8KRL2）的 Developer ID Installer 签名和公证。
  - 只展开、不安装，只取 `podman/bin/gvproxy`，固定 SHA-256；把安装包的隔离属性带到这份副本上；再核对 Developer ID Application 签名、标识 `gvproxy` 和 Gatekeeper 的公证评估。
  - 它是上游 gvisor-tap-vsock v0.9.0，Go 构建信息里的提交与官方 v0.9.0 标签相同，命令行和配置文件格式与原来一致，包过滤规则不用改。
  - 是否运行仍由 macOS 决定；不删隔离属性、不重签、不改 Gatekeeper、不回退普通 NAT。
- **已发布的旧 VM**（包括 bb1）：确认启动时，如果运行环境还是旧版（旧后端或后端副本缺失），管理器先下载并核对安装包、取出 gvproxy，再用当前的启动文件和这份后端替换旧的；VM 配置、Tart 绑定、`policy.json`、两份收据和状态目录保持不变并重新核对，有任何变化就拒绝。失败报 `backend_refresh_failed`，不会启动。
- **隔离属性的核对**改为「必须一直存在」：Gatekeeper 评估过公证程序后可能更新标志位，值可以变，但被删除就拒绝。
- **改动的文件**：`host_artifacts.py`、`host_tools.py`（`ensure_gvproxy`；读取已下载材料时改用共享锁，否则 `pkgutil` 会一直等）、`preinstall_runtime.py`、`protected_launcher.py`（只改帮助文字）、`manager.py`、`oneclick.py`、`static/app.js`，以及对应测试和文档。
- **客机实测**：用真实的安装包和系统自带的 `pkgutil`、`codesign`、`spctl` 跑过一遍下载、核对和提取，结果符合预期；gvproxy 本身没有运行过。
- **没有验证**：宿主上真实启动 bb1、Gatekeeper 是否放行、启动两次后隔离属性的变化、首次桌面和 VPN 连通。

### 首次设置改用普通网络（追加）

- **起因**：签名版后端生效后 bb1 能开机，但 macOS 26 设置助理选完「成人」后一直转圈，一小时没动。受保护网络只放行 VPN 节点，DNS 和 Apple 服务器的包都被静默丢弃；客机拿到了地址，以为自己联网了，于是一直等。
- **负责人决定（2026-11-19）**：Clash 装好之前这层保护没有意义。首次设置默认用普通网络；装好 Clash 且配置生效后，之后每次启动都走管理器的受保护启动。
- **做法**：
  - 运行目录里新增宿主专用记录 `network-mode.json`，不在受审清单里。没有这个文件就是「首次设置中」；用户点 **标记首次设置完成…** 后写入 `{"version":1,"mode":"protected"}`，不能撤销。内容、权限不对或是符号链接都拒绝（`invalid-network-mode`），也不会被覆盖。
  - 首次设置时，启动器带 `--first-setup-normal-network`：照常加锁、完整校验、核对 VM 身份和共享，然后运行 `tart run <vm> --no-clipboard`，挂状态目录和用户共享，不带 `--net-fd`，由 Tart 用它自己的 NAT。不运行网络后端，也不加执行位，没有包过滤。标记完成后这个参数会被拒绝（`first-setup-finished`）。
  - 管理器：首次设置中只接受 `first_setup_normal_network:true` 加完整 VM 名称的启动，不接受后端授权字段；标记完成后只接受原来的受保护启动。新增动作 `finish-first-setup`。状态里加了 `preinstalled.first_setup_pending` 和 `network.normal_network`。
  - 界面：首次设置中按钮写「首次设置启动…」，确认框说明这次不经过过滤、Apple 会看到本机真实 IP；运行时显示「首次设置 · 普通网络，未过滤」；另有「标记首次设置完成…」按钮。
  - **让已发布的 VM 拿到新启动器**：运行目录里的启动器是发布时复制的旧版本，不认识新参数。每次确认启动前，如果运行环境完整、后端已是签名版，`refresh_sources` 会把代码文件换成当前版本（先完整校验，任何变化都拒绝；只改 `source_sha256`；后端副本、隔离属性、过滤规则、收据都不动，不下载）。
- **为什么要用户手动标记**：管理器看不到 Clash 是否真的连上（客机回执只说「已导入」）。自动切换可能在 Clash 没生效时就切到受保护启动，客机就又没网了。
- **改动的文件**：`preinstall_runtime.py`、`protected_launcher.py`、`manager.py`、`oneclick.py`（两句说明）、`static/app.js`，以及对应测试和文档。`packet_policy.py` 没改，固定的 SHA-256 不变。
- **客机测试**：Python 878 项，只有已知的 `test_compiler_system_temp…` 失败（改动前 865 项，同一个失败）；Node 44/44（改动前 43）。
- **没有验证**：宿主上普通网络下设置助理能否走完、Tart 自带 NAT 在宿主上能否联网、首次登录后 Clash 导入和连接、标记完成后受保护启动能否通过节点上网。

### 不再写客机磁盘（追加，2026-11-20）

- **起因**：bb1 首次登录后 Clash Verge 报「正在从 App Translocation 临时路径运行」并退出。应用是宿主复制进客机 `/Applications` 的，带着下载隔离标记却从没被 Finder 移动过，macOS 就把它们放到随机的只读路径运行；Clash Verge 2.5.10 的 `macos_launch_guard.rs` 检查到就退出。另外三个应用也一样被放进临时路径（不能自动更新）。不清除隔离标记就只能让用户用 Finder 移动，所以改成在客机里安装。
- **负责人决定**：按简化流程重写。
- **新流程**：恢复系统 → 重新校验 4 个应用并用 APFS 克隆进安装文件夹，写入节点配置和说明 → 发布 v3 运行环境 → 首次设置用普通网络，挂只读 `gold-installers` → 用户安装、导入、开 TUN、确认连通 → 关机后标记完成 → 之后只走受保护启动，不再挂安装文件夹。
- **运行环境 v3**（`preinstall_runtime.py`）：没有收据和状态邮箱，记录 `installers` 文件夹的 device/inode。v2（bb1）照旧校验和启动，启动器同时认 2 和 3。
- **删除**：`offline_preinstall.py`、`offline_vpn.py`、`offline_install.py`（材料类型移到 `preinstall_materials.py`）、`offline_writable.py`、`offline_recovery.py`、`offline_disk.py`、`guest_ownership.py`、`GuestOwnershipHelper.swift`、`guest_vpn_seed.py`、`GuestVPNBootstrap.swift`、对应测试和三份文档；管理员授权暂停（接口、状态字段、界面）；`acknowledge_guest_autoconfigure`。只编译 CleanVMInstaller。
- **顺带修复**：
  - **bb1 删不掉**：旧属主助手以 root 身份在 VM 目录里写了 `.guest-ownership/<编号>/apply.started`、`verify.started`，删除前检查拒绝任何不属于当前用户的文件。现在只对这两类标记放行（`lifecycle.legacy_ownership_marker`），其他异常文件照旧拒绝。
  - **不再要求输入 VM 名称**：所有确认对话框改为点一下按钮。接口里的 `confirm_name` 仍然检查，由界面自动填入当前对话框对应的 VM。
- **版本**：App 1.4.0（build 7）。

### 再建一台时沿用镜像和节点（追加，2026-11-22）

第二台 VM 不用再填 YAML 路径，也不用再选或再下载系统镜像。不涉及客机磁盘，也不复制已有 VM。

- **节点**：票据仍是一次性、一小时过期，这一点没有变。新增的是从已有 v3 VM 的私有环境读回它构建时用的那份配置，再发一张新票据。[preinstall_runtime.py](<preinstall_runtime.py>) 的 `saved_private_config` 只读 `installers` 里的节点配置文件，摘要必须等于环境里钉住的 `private_config_sha256`，端点必须等于该环境的 `policy.json`；[vpn_store.py](<vpn_store.py>) 的 `store_saved` 不查 DNS 重新解析，结果必须与输入逐字节一致，摘要里没有归一化警告（没有任何东西被替换）。校验接口多一种 `{input_mode:"vm",vm:"<名称>"}`，`allow_resolve` 必须为 `false`；未知 VM、v2 环境（bb1 这类，没有 installers）和文件被改动，都回同一句拒绝。
- **镜像**：缓存本来就会复用（选「经审核的固定镜像」时不再下载，只重新核对哈希），问题只是界面没说。[host_artifacts.py](<host_artifacts.py>) 新增 `cached`，只看记录、文件身份和大小，不哈希、不加锁；能力接口多一个 `restore_image_cached`，对话框据此显示「不再下载，也不用选文件」。再选一次本机 IPSW 会另存一份约 20 GB 的副本（`import_local` 总是复制），界面也会提示。
- **界面**：有可沿用的 VM 时「节点来源」默认选它，仍要点一次「沿用并校验这组节点」；改回「填写新的节点」就是原来的 YAML 路径或手工表单。待配置 VPN 的续接任务同样可以沿用。
- **没做的**：复制已有 VM 再清理、恢复后未开机的模板盘，都没有做。

### 宿主与客机共享剪贴板（追加，2026-11-23）

负责人要求新建的 VM 也有剪贴板共享（之前只在 gold fresh 里手动装过），并决定**默认开启，不让用户选择**。客机磁盘仍然不写；agent 由用户在首次设置时自己装。

- **原理**：Tart 只要不带 `--no-clipboard`，就给 VM 加一个 SPICE agent 控制台端口（virtio console，不是网卡，和 `--net-fd`、包过滤无关）。macOS 客机里必须运行 [tart-guest-agent](https://github.com/openai/tart-guest-agent) 的剪贴板组件 `--run-vdagent` 才能用。以前 v2/v3 的每次启动都固定带 `--no-clipboard`。
- **宿主材料**（[host_artifacts.py](<host_artifacts.py>)、[host_tools.py](<host_tools.py>)）：固定 `tart-guest-agent` 0.15.0 的 `tart-guest-agent-darwin-all.tar.gz`（10,057,123 字节，SHA-256 `eb47f402…80b7`，发布方 GitHub 摘要，与其 Homebrew 配方一致）。`ensure_guest_agent` 只接受顶层的 `tart-guest-agent` 加最多 `LICENSE`、`LICENSE.md`、`README.md`、`CHANGELOG.md`，其他任何成员、链接、目录、setuid、可写权限都拒绝；静态核验 arm64、`Developer ID Application: Cirrus Labs, Inc. (9M2P8L4D89)`、标识 `tart-guest-agent`、`Notarized Developer ID`；隔离属性传给副本并保留。宿主从不运行它。`load_guest_agent` 按回执重新核验（等待配置 VPN 的续接用它）。
- **安装文件夹**（[oneclick.py](<oneclick.py>) `build_installers`）：多一个 `剪贴板共享/`：agent 副本（0644，哈希和隔离属性逐项核对）、发布包里的文档、按这份哈希生成的 `安装剪贴板共享.command`（0755）和 `说明.txt`（用法、卸载、许可证链接）。「先读我.txt」新增第 2 步。
- **客机脚本**：只用系统自带工具，不联网、不用 sudo、不改隔离属性。核对哈希和签名要求后，把 agent 复制到 `~/Library/Application Support/GoldClipboard/`，写 `~/Library/LaunchAgents/org.goldvm.clipboard-agent.plist`（只有 `--run-vdagent`，没有 `--run-rpc`/`tart exec`、root 守护进程或磁盘扩容），`launchctl bootstrap gui/<uid>`，再看 `/dev/cu.com.redhat.spice.0` 报告结果。可重复运行。
- **启动**（[preinstall_runtime.py](<preinstall_runtime.py>)）：`prepare_environment(..., share_clipboard=True)` 在私有环境里写 `clipboard.json`（精确内容 `{"version":1,"clipboard":"shared"}`，0600，像 `network-mode.json` 一样在受审清单之外）。有这条记录时，首次设置和受保护启动都不带 `--no-clipboard`；恢复模式始终带。没有记录（2026-11-23 之前建的全部 VM，以及所有 v2）照旧带。内容、权限、链接或属主不对就拒绝启动（`invalid-clipboard-record`），不修复也不覆盖。旧的 v1 启动器（gold fresh 用的）没有改动。
- **续接兼容**：暂停待配置 VPN 的检查点多一个 `guest_agent`；旧版写的检查点没有它，续接时会补下载并核验 agent。
- **界面和文档**：首次设置确认框和卡片提到剪贴板共享；新增失败代码在 `static/app.js` 里有中文原因；README（中英）、一键预装指南、运行环境说明、宿主材料说明已更新。版本 1.5.3。
- **安全边界**：剪贴板是双向通道。VM 运行期间宿主复制的内容（包括密码管理器里的密码、节点资料）可能进客机，反之亦然。不经过网络，不暴露宿主 IP。tart-guest-agent 是 FSL-1.1-ALv2，在宿主上按固定版本从官方发布页下载，不随源码分发。
- **没验证的**：发布包的实际成员（没在客机里下载；若宿主报 `unexpected-guest-agent-archive` 就按实际结构调整）；带隔离属性、已公证的命令行程序由 launchd 启动时 macOS 是否放行；真实 VM 里两个方向的复制粘贴。

## 验证

### 宿主实机已完成预装并发布（2026-11-19）

- 宿主 macOS 26.6.2 / 25G83 使用 `fea71e5` 的 V2 属主助手：复用已校验应用缓存，完成系统恢复、四个应用预装和 VPN 配置写入，任务进入 `awaiting_first_desktop_acceptance`。已确认发布目录和磁盘存在。
- 尚未启动该客机；首次桌面和 VPN 连通性仍未验收。宿主自动化回归为 913 项 Python、43 项界面测试全部通过。

### 本轮在客机里的结果

客机没有 Command Line Tools，所以改用独立的 Python 3.9.25 和 Node 22 运行时，按摘要校验后使用。

| | 改动前 | 改动后 |
| --- | --- | --- |
| Python | 784 个，5 个失败 | 812 个，同样 5 个失败，没有新增失败 |
| Node | 34/34 通过 | 37/37 通过 |

这 5 个失败都与本轮改动无关：

- 3 个 Swift fixture 的 `setUpClass`：客机没有 swiftc，包括 `test_CleanVMInstaller`、`test_guest_ownership.SwiftOwnershipFixtureTests`、`test_guest_vpn_seed.SwiftFixtureTests`。
- `test_prepare_preserves_config_posix_lock_and_offset`：需要 `/usr/bin/python3` 子进程。
- `test_host_tools…test_compiler_system_temp_requires_os_location_owner_and_exact_private_mode`：改动前就失败，原因未查，在宿主上应复查。

**没有验证的部分**：

- Swift 代码的编译。
- 宿主上的打包和签名。
- 真实 osascript 的 stderr 格式：只用 fixture 测过。
- 失败卡片在 WKWebView 里的实际显示。
- 真实的预装和归档。

### 在宿主上要做的

1. 用 `git diff` 审查本轮改动，然后提交。
2. 在仓库根目录跑完整测试。宿主有 Command Line Tools，Swift 测试也应该通过：

   ```sh
   /usr/bin/python3 -B -m unittest discover -s tests -p 'test_*.py'
   node --test tests/test_offline_ui.js tests/test_preinstall_ui.js
   ```

3. 按 [源码安装说明](<SOURCE_INSTALL.md>) 构建到一个**不存在的新路径**。安装器不会覆盖已有的 App，正在运行的旧版也不会自动更新。
4. 用新版先归档旧的失败任务，再新建一次预装。
5. 如果仍然失败，记下卡片上的「失败步骤」和「代码」，按上表决定下一步。只记录固定代码，不要附带原生日志、路径或节点信息。

宿主已经用验签后的诊断版归档了上一项失败任务：只移动任务记录，复核了暂存盘、VM 配置和应用回执的文件身份均未变化，暂存盘仍未挂载、未发布、未开机。没有通过旧故障推断新的失败代码；下次复现时需先确认正在运行的是诊断版控制器，而非同版本号的旧后台。

测试使用自有的临时 fixture，不会安装或启动虚拟机。构建后的本地签名不等于 Developer ID 公证。首个已审查组合是 Apple Silicon / macOS 26.6.2，恢复镜像固定为 26.6.2 / 25G83。源码构建需要系统 Python 3.9+、Ruby/Psych，以及 Apple Command Line Tools 或选定的 Xcode SDK。Node 只用于运行界面测试。

## 待办（按优先级）

1. ~~根据诊断结果修复管理员授权（B2）。~~ 2026-11-20 删除了属主助手和管理员授权，不再需要。
2. **移除实验性代码（D）。** [NativeApp.swift](<NativeApp.swift>) 仍然注册了账户初始化桥：包括密码表单、辅助功能和屏幕录制权限请求、同意 macOS 许可的勾选框，前端也能触发它；但 README 写的是「未交付」。另外，[deploy_rebuild_update.py](<deploy_rebuild_update.py>) 的文件清单缺少 `oneclick.py` 等文件，执行后会让已安装的 App 无法启动，而且它用 `assert` 做安全检查。
3. **非破坏性恢复和首次启动仍未验收。**
   - 已进入私有配置写盘后才失败的任务，与主动选择「先不配置 VPN」的干净等待状态不同。
   - 失败任务**只能归档**，不能直接改成可续接；不能重用旧授权票据、跳过只读验收、覆盖现有盘，也不能把未验证状态标成成功。
   - 没有真实授权和获准的配置时，不得执行实机连通测试。
   - gvproxy 已换成 Red Hat 签名并公证的版本（见上文「网络后端换成 Red Hat 签名并公证的 gvproxy」），仍不能清除隔离属性或降低 Gatekeeper 检查。
   - 首次设置用普通网络并挂只读安装文件夹（见上文「不再写客机磁盘」），宿主上还没走通过：设置助理、从共享文件夹用 Finder 安装、Clash 导入本地订阅、标记完成后的受保护启动都要实测。
4. **验收分级。** 分别记录以下各项是否成功：软件和磁盘核验、属主核验、事务发布、首次桌面、导入自报、VPN 连通。独立 fixture 通过、宿主打包成功或客机回执，都不代表真实 VM 的网络已经验收。
5. **审查中其余未处理的问题。**
   - 宿主系统被精确锁定在 26.6.2（`host_tools.py`、`install_app.py`），系统小版本一更新就无法构建和预装。建议改为 ≥26.0 即可，遇到未审查的版本给出警告。
   - 控制器在全局锁内运行 `tart list`，每次状态轮询都跑 `sysctl` 和 `ps`。
   - 包转发每轮循环都重新解析 `control.json`，每个 socket 每轮只收一个包。
   - 版本号在 `bootstrap.py` 和 `manager.py` 中各写一份，与 API 文档也不一致。
   - 硬编码的 VM 名：`gold`、`gold-backup`、`gold-fresh`。
   - 安全文件读写函数重复实现了约 15 份，检查项各不相同。
   - 「打开窗口」每次都用 `swift -e` 现场编译。
   - `/tmp/goldnet-*` 目录从不清理。
   - 没有格式化工具、代码检查或 CI。
6. **架构问题。** ~~是否放弃「宿主离线写客机磁盘」~~：已决定放弃（2026-11-20）。宿主版本锁定（第 5 项第一条）仍在，可以单独放宽。控制器仍依赖 Command Line Tools 自带的 `/usr/bin/python3`（3.9，已停止维护），没装 CLT 的 Mac 无法运行。

## 改代码时要注意

- **失败代码只能是固定 slug。** 新增代码时，要同时：
  - 在 `error_codes.py` 或抛出处给出 slug；
  - 在 `static/app.js` 的 `steps` / `reasons` 映射表里补上中文；
  - 在测试里断言原始文本不会出现在状态 JSON 中。
- **界面测试的取函数方式有限制。** `tests/test_*_ui.js` 用 `declaration(name)` 从 `app.js` 截取单个函数，截取范围到第一个 `\n  }` 为止。函数内部如果有缩进两格的 `}`，就会截错。
- **打包清单是手写的。** 新增的 Python 模块必须加进 `install_app.py` 的 `FILES`，本轮已加入 `error_codes.py`。
- **不要提交本地数据。** 公开任务请使用合成样例和最小错误类别。不要把本机 `evidence/`、管理器状态、原始凭据或已填入真实节点的配置加入 Git。更多边界见 [安全说明](<SECURITY.md>) 和 [一键预装指南](<ONE_CLICK_PREINSTALL.md>)。
