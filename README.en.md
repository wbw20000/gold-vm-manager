# Gold VM Manager

**[Join the Gold VM WeChat group](https://weixin.qq.com/g/AQYAAMoC6cPVM_wJbKwTY4TAaGCjDxIoHfW81qVt9QjcPD3nTesOm66syMumSJMb)** · Scan with WeChat, or long-press the code in WeChat on mobile. Group invitations expire.

<a href="docs/media/wechat-group.png?raw=true"><img src="docs/media/wechat-group.png" width="180" alt="Gold VM WeChat group QR code; click to enlarge"></a>

Run Claude Code in a dedicated macOS VM on an Apple Silicon Mac. First setup uses ordinary networking. After setup, Protected Start restricts outbound traffic to the configured proxy endpoints rather than falling back to a direct connection.

**[Download v1.4.0 source](https://github.com/wbw20000/gold-vm-manager/releases/tag/v1.4.0) · [Watch the 23-second install guide](docs/media/guest-install.gif?raw=true) · [Download and fill in the YAML](#download-and-fill-in-the-yaml-host-mac) · [After installing the four apps](#after-installing-the-four-apps-guest) · [简体中文](README.md)**

> **My experience (last personally confirmed: 2026-11-21):** I use this VM for Claude Code. I used Pro for four days without a ban, then upgraded to Max. On my second day of Max, my account was still active. [Why I built this ↗](https://x.com/clarkwang258/status/2123747367639994757)
>
> **Calendar day since my Max upgrade: <!-- max-days:start -->4<!-- max-days:end -->.** This counter follows the Singapore calendar. It does not sign in to Claude or verify my account status; the dated note above is my personal observation.

[![The actual manager interface showing a VM list and controls](docs/media/manager-overview.png)](docs/media/manager-overview.png?raw=true)
*Actual interface with demo data. Click to enlarge.*

## Install the manager (host Mac)

1. **Check first:** Apple Silicon, macOS **26.6.2** (validated version), Apple Command Line Tools or Xcode, system Python 3.9+, and system Ruby with Psych. The default 50 GiB guest disk needs at least **82 GiB** free on the host. Leave additional room for the restore image and cache.
2. On the [v1.4.0 release page](https://github.com/wbw20000/gold-vm-manager/releases/tag/v1.4.0), download **Source code (zip)** and extract it. Double-click [Install.command](Install.command) or run `./Install.command` from the source directory. Open **Gold VM 管理器** in `~/Applications`.
3. This is a **locally ad-hoc signed source build**, not a notarized app download. It neither overwrites an existing app nor starts a VM. Leave Gatekeeper enabled. See [build options](SOURCE_INSTALL.md) for a side-by-side installation.

## Download and fill in the YAML (host Mac)

1. **Download.** In **新建 VM 及预装软件** (Create VM and Prepare Apps), click **下载 YAML 填写模板**. Alternatively, open the [template on GitHub](examples/vpn/clash.yaml) and click **Download raw file** at the top right. If the [raw YAML](https://raw.githubusercontent.com/wbw20000/gold-vm-manager/v1.4.0/examples/vpn/clash.yaml) opens as text in your browser, press `⌘S`. Save it **outside the repository** as `clash.local.yaml`, not `.yaml.txt`.
2. **Choose a protocol.** Open the file in a plain-text editor. Change `proxies: []` to `proxies:`. Find the block matching your node's protocol and remove the leading `# ` from its configuration lines, keeping the indentation. Leave the other blocks commented. Do not paste a subscription URL into `server`.
3. **Fill in your provider's values.** For Trojan TLS/TCP, `server` is your node's public address, `port` is its numeric port, `password` is the node password, and `sni` is the provider's TLS hostname. This example shows the structure only; its values cannot connect. For VLESS, TUIC or another protocol, use that protocol's fields instead.

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

4. **Validate the local file.** Save it, select it in the host Finder, and press `⌥⌘C` to copy its full path. Paste it into **本地 Clash YAML 绝对路径** (Local Clash YAML absolute path). Enter a new VM name, select the restore image, then click **校验并私有保存节点 → 同意并开始预装** (Validate and Save Privately → Confirm and Start). If `server` is a hostname, explicitly allow local resolution. Validation checks the configuration, not connectivity. [View the creation dialog](docs/media/manager-create.png?raw=true).

**Where are credentials stored?** Your filled YAML is not uploaded to GitHub. The manager stores plaintext credentials in a private host directory and exposes them in a read-only guest share during setup. Read-only is not encryption. Do not distribute the file or VM disk. Choose **先不配置 VPN** (Configure VPN Later) if you want to restore macOS before supplying a node.

## First run: what to do next

| What you see | Next step |
| --- | --- |
| **未启动 · 待首次设置** (Stopped · First Setup Pending) | Choose **首次设置启动…** (Start First Setup) and confirm **ordinary, unfiltered networking** for this boot. Complete macOS setup and enter the guest desktop. |
| **Finder → My Shared Files → gold-installers** | Read **先读我.txt** (Read Me First). Drag each of the four apps **to the guest Desktop, then from the Desktop to Applications**. Do not run them from the share. |
| **Four apps in Applications** | There is no need to launch them all. Configure Clash Verge, check the connection with CCBaga A, then use Claude as described below. |

[![Illustrated Finder workflow: shared folder to guest Desktop, then Desktop to Applications](docs/media/guest-install.gif)](docs/media/guest-install.gif?raw=true)
*[Enlarge looping animation](docs/media/guest-install.gif?raw=true) · [Static steps](docs/media/guest-install.png?raw=true). Illustrated guide, not a guest recording.*

## After installing the four apps (guest)

1. **Connect the proxy in Clash Verge.** Open it from Applications. Go to **Subscriptions → New → Local → Choose File**, select **My Shared Files → gold-installers → Clash 节点配置.yaml**, save, then click the new profile to activate it. This is the guest configuration generated by the manager, **not the blank GitHub template**.
2. **Enable TUN and check traffic.** Turn on **TUN mode** in Clash Verge settings and approve the service installation inside the guest. Load a webpage in the guest, then check **Connections** in Clash: the request should use the selected node, not `DIRECT`. A page loading over the ordinary first-setup network is not proof the proxy works.
3. **Check the environment in CCBaga A.** Open **浏览器环境** (Browser Environment) to run the checks. Use **电脑环境** (Computer Environment) to align the time zone; if you do not need location access, turn off Location Services in the guest’s Privacy & Security settings. Run the checks again. This walkthrough uses **A**; you do not need to open **CCBaga B** alongside it. Once all checks are green, the optional [IP/DNS check](https://ip.net.coffee/claude/) uses **70 or higher and no reported IP or DNS leak** as a reference. It is not a Claude eligibility test. Never enter credentials there.
4. **Switch to Protected Start.** After confirming the proxy works, shut down normally **inside the guest**. In the host manager select **标记首次设置完成…** (Mark First Setup Complete), then **受保护启动…** (Protected Start). The marker cannot be undone. The installer share is no longer mounted. Recheck Clash connections after startup.
5. **Use Claude.** For the graphical app, open **Claude Desktop** from the guest’s Applications folder. For the CLI, follow the [official Claude Code guide](https://code.claude.com/docs/en/quickstart) **inside the guest**, then run `claude` in the guest terminal and follow the official sign-in prompt. Installing Desktop does not install Code.

[Troubleshooting: disk space, setup spinner, or Clash running from a temporary path](docs/first-run-troubleshooting.md#english) · [Full guide (Chinese)](ONE_CLICK_PREINSTALL.md) · [Security](SECURITY.md)
