# Gold VM Manager

[简体中文](README.md) · English

Create a dedicated macOS VM on an Apple Silicon Mac and use **Claude Code** inside it. The goal is to reduce risks from mixing host and guest configurations or connecting directly when a proxy drops. **A VM cannot prevent account bans or change Claude's region, account, or plan eligibility.**

[![Gold VM Manager interface showing the VM list and controls](docs/media/manager-overview.png)](docs/media/manager-overview.png?raw=true)
*Actual manager interface with demo data. Click to enlarge.*

## 1. Install the manager (host Mac)

- **Requirements:** Apple Silicon, macOS **26.6.2** (the only version validated so far), Apple Command Line Tools or Xcode, system Python 3.9+, and system Ruby with Psych.
- Choose **Code → Download ZIP** on GitHub and extract it. Double-click [Install.command](Install.command), or run `./Install.command` from the source directory. Then open **Gold VM 管理器** in `~/Applications`.
- GitHub does not provide a prebuilt installer. The installer does not overwrite an existing copy or start a VM. See the [source installation guide](SOURCE_INSTALL.md) to build to a different path.

## 2. Create a VM (host manager)

1. Select **新建 VM 及预装软件** (Create VM and Prepare Apps), enter a new name, and keep the reviewed Apple restore image or select a local IPSW for that same version. The default 50 GiB virtual disk requires at least **82 GiB** free on the host; allow additional space to download or import the image.
2. Copy the [blank Clash YAML template](examples/vpn/clash.yaml) outside the repository and fill in a node you are authorized to use. Enter the local path in the manager, select **校验并私有保存节点** (Validate and Save Privately), then **同意并开始预装** (Confirm and Start). Do not commit real YAML files, VPS addresses, or credentials.
3. Wait for **未启动 · 待首次设置** (Stopped · First Setup Pending). The manager prepares macOS and the installer files without starting the VM or handling login or approvals on your behalf. [View the VM creation dialog](docs/media/manager-create.png?raw=true).

## 3. First setup (inside the VM)

1. Select **首次设置启动…** (Start First Setup) and confirm **ordinary, unfiltered networking** for this boot. Complete macOS setup and enter the guest desktop.
2. In the guest Finder, open **My Shared Files → gold-installers** and read **先读我.txt** (Read Me First). Drag each of the four apps **to the guest Desktop first, then from the Desktop to Applications**. Do not launch the apps directly from the share.
3. Open **Clash Verge** from Applications. Import the shared config via **Subscriptions → New → Local**, then enable **TUN mode**. Approve any service-installation prompt inside the guest. Check that connections actually use your proxy; an ordinary webpage loading does not prove that.
4. For Claude Code, follow the [official instructions](https://code.claude.com/docs/en/quickstart) to install it and sign in inside the guest. The included **Claude Desktop** installer is not Claude Code.

[![Install all four apps individually: shared folder to guest Desktop, then Desktop to Applications](docs/media/guest-install.gif)](docs/media/guest-install.gif?raw=true)
*Illustrated Finder walkthrough (loops; not a guest recording). [Enlarge animation](docs/media/guest-install.gif?raw=true) · [Static step-by-step view](docs/media/guest-install.png?raw=true)*

## 4. Use Protected Start afterward

Once Clash is working, **shut down the guest normally**. In the manager, select **标记首次设置完成…** (Mark First Setup Complete), then **受保护启动…** (Protected Start). The installer share is no longer mounted, and outbound traffic is filtered. A backend or proxy failure does not fall back to ordinary networking. The first-setup completion marker cannot be undone.

[Detailed setup and troubleshooting (Chinese)](ONE_CLICK_PREINSTALL.md) · [Security and credentials](SECURITY.md) · [Development handoff](DEVELOPMENT_HANDOFF.md)
