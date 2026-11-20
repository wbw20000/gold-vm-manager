# Gold VM Manager · 开发交接

这是可独立构建的源码仓库，不是虚拟机镜像或已公证安装包。**Claude 在客机运行；宿主只负责管理。** 这里不包含开发机器上的状态、节点、账号、日志、第三方二进制或测试磁盘。

## 当前状态（2026-11-18）

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
| 新建、预装和续接 | [流程编排](<oneclick.py>)、[生命周期与状态](<lifecycle.py>)、[Apple 恢复助手](<CleanVMInstaller.swift>)、[离线预装](<offline_preinstall.py>)、[APFS 归属](<offline_volume.py>)、[发布保护](<preinstall_runtime.py>)。系统与应用从受审查的固定来源获取，不从开发机器复制。 |
| Clash 配置 | [公开占位模板](<examples/vpn/clash.yaml>)、[解析与策略](<vpn_config.py>)、[本地路径与私有票据](<vpn_store.py>)、[写盘与验收](<offline_vpn.py>)、[首次登录助手](<GuestVPNBootstrap.swift>)。界面默认填本地 YAML 绝对路径，也可先预装、后补 VPN。 |
| 系统授权和网络 | [授权请求及回执](<guest_ownership.py>)、[固定属主助手](<GuestOwnershipHelper.swift>)、[受保护启动](<protected_launcher.py>)、[端点过滤](<packet_policy.py>)。没有普通 NAT 回退。 |
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

1. **根据诊断结果修复管理员授权（B2）。** 两项都需要改 Swift，并在宿主上编译和实测。
   - **TOCTOU 风险**：[`request_authorization`](<guest_ownership.py:624>) 先以普通用户身份校验 helper，再让 root 执行同一个用户可写路径。等待输入密码期间，同 UID 的进程可以替换这个文件。
     - **修法**：在 root 脚本里先把 helper 复制到只有 root 可写的目录，用 root 重新计算 sha256，比对一致后再执行。
     - **注意**：helper 会检查 [`argv[0] == ticket.helper`](<GuestOwnershipHelper.swift:316>)，需要同步修改这项检查。
   - **改由原生 App 发起授权**（Authorization Services）仍待办。helper 固定失败类别已实现，历史任务的 `exit(2)` 无法追溯。
2. **移除实验性代码（D）。** [NativeApp.swift](<NativeApp.swift>) 仍然注册了账户初始化桥：包括密码表单、辅助功能和屏幕录制权限请求、同意 macOS 许可的勾选框，前端也能触发它；但 README 写的是「未交付」。另外，[deploy_rebuild_update.py](<deploy_rebuild_update.py>) 的文件清单缺少 `oneclick.py` 等文件，执行后会让已安装的 App 无法启动，而且它用 `assert` 做安全检查。
3. **非破坏性恢复和首次启动仍未验收。**
   - 已进入私有配置写盘后才失败的任务，与主动选择「先不配置 VPN」的干净等待状态不同。
   - 失败任务**只能归档**，不能直接改成可续接；不能重用旧授权票据、跳过只读验收、覆盖现有盘，也不能把未验证状态标成成功。
   - 没有真实授权和获准的配置时，不得执行实机连通测试。
   - gvproxy 已换成 Red Hat 签名并公证的版本（见上文「网络后端换成 Red Hat 签名并公证的 gvproxy」），仍不能清除隔离属性或降低 Gatekeeper 检查。
   - `offline_recovery.py` 被打包了，但没有任何模块导入它，也没有命令行入口；仍缺一个只读的诊断命令。
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
6. **需要负责人决定的架构问题。** 是否放弃「宿主离线写客机磁盘」，改为在客机内用可见的安装器安装？这样做可以去掉宿主 root 授权、APFS 布局依赖和宿主版本锁定（上面第 1 项和第 5 项的第一条），代价是首次登录后用户要多做一步。另外，控制器依赖 Command Line Tools 自带的 `/usr/bin/python3`（3.9，已停止维护），没装 CLT 的 Mac 无法运行。

## 改代码时要注意

- **失败代码只能是固定 slug。** 新增代码时，要同时：
  - 在 `error_codes.py` 或抛出处给出 slug；
  - 在 `static/app.js` 的 `steps` / `reasons` 映射表里补上中文；
  - 在测试里断言原始文本不会出现在状态 JSON 中。
- **界面测试的取函数方式有限制。** `tests/test_*_ui.js` 用 `declaration(name)` 从 `app.js` 截取单个函数，截取范围到第一个 `\n  }` 为止。函数内部如果有缩进两格的 `}`，就会截错。
- **打包清单是手写的。** 新增的 Python 模块必须加进 `install_app.py` 的 `FILES`，本轮已加入 `error_codes.py`。
- **不要提交本地数据。** 公开任务请使用合成样例和最小错误类别。不要把本机 `evidence/`、管理器状态、原始凭据或已填入真实节点的配置加入 Git。更多边界见 [安全说明](<SECURITY.md>)、[一键预装指南](<ONE_CLICK_PREINSTALL.md>) 和 [属主授权契约](<GUEST_OWNERSHIP.md>)。
