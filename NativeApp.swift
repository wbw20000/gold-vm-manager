import AppKit
import WebKit
import Foundation
import ApplicationServices
import CoreGraphics

@MainActor
final class Delegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKScriptMessageHandler {
    var window: NSWindow!
    var web: WKWebView!
    var placeholder: NSTextField!
    private var initialization: GuestInitializationDriver?
    private var credentials: GuestInitializationDriver.Credentials?
    private var connecting = false
    private var powerActivity: NSObjectProtocol?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let main = NSMenu(), item = NSMenuItem(), menu = NSMenu()
        main.addItem(item)
        menu.addItem(withTitle: "退出 Gold VM Manager", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = menu
        let editItem = NSMenuItem(title: "编辑", action: nil, keyEquivalent: ""), edit = NSMenu(title: "编辑")
        edit.addItem(withTitle: "撤销", action: NSSelectorFromString("undo:"), keyEquivalent: "z")
        let redo = edit.addItem(withTitle: "重做", action: NSSelectorFromString("redo:"), keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command,.shift]
        edit.addItem(.separator())
        for (title,selector,key) in [("剪切","cut:","x"),("复制","copy:","c"),("粘贴","paste:","v"),("全选","selectAll:","a")] {
            edit.addItem(withTitle: title, action: NSSelectorFromString(selector), keyEquivalent: key)
        }
        editItem.submenu = edit; main.addItem(editItem)
        let viewItem = NSMenuItem(title: "显示", action: nil, keyEquivalent: ""), view = NSMenu(title: "显示")
        let reload = view.addItem(withTitle: "重新连接并刷新界面", action: #selector(reloadInterface), keyEquivalent: "r"); reload.target = self
        let cancel = view.addItem(withTitle: "停止自动初始化（不关闭 VM）", action: #selector(cancelInitialization), keyEquivalent: "."); cancel.target = self
        let permissions = view.addItem(withTitle:"检查自动初始化权限…",action:#selector(checkInitializationPermissions),keyEquivalent:"");permissions.target=self
        viewItem.submenu = view; main.addItem(viewItem); NSApp.mainMenu = main
        window = NSWindow(contentRect: NSRect(x:0,y:0,width:1280,height:860), styleMask:[.titled,.closable,.miniaturizable,.resizable], backing:.buffered,defer:false)
        window.title = "Gold VM Manager · 本机虚拟机与共享目录"; window.minSize = NSSize(width:900,height:650); window.center()
        let config = WKWebViewConfiguration()
        config.userContentController.add(self,name:"startGuestInitialization")
        web = WKWebView(frame:window.contentView!.bounds,configuration:config)
        web.autoresizingMask = [.width,.height]; web.navigationDelegate = self
        window.contentView!.addSubview(web)
        placeholder = NSTextField(labelWithString:"正在连接本机管理服务…")
        placeholder.font = .systemFont(ofSize:17,weight:.medium); placeholder.alignment = .center
        placeholder.frame = NSRect(x:230,y:390,width:820,height:60)
        placeholder.autoresizingMask = [.minXMargin,.maxXMargin,.minYMargin,.maxYMargin]
        window.contentView!.addSubview(placeholder)
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps:true)
        connect()
    }

    private func connect() {
        guard !connecting else { return }
        connecting = true; placeholder.isHidden = false; placeholder.stringValue = "正在连接本机管理服务…"
        let script = Bundle.main.resourceURL!.appendingPathComponent("app/bootstrap.py")
        DispatchQueue.global(qos:.userInitiated).async { [weak self] in
            let p = Process(), output = Pipe()
            p.executableURL = URL(fileURLWithPath:"/usr/bin/python3"); p.arguments = [script.path,"--emit-url"]
            p.environment = ["HOME":FileManager.default.homeDirectoryForCurrentUser.path,"PATH":"/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin","LANG":"en_US.UTF-8","PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1"]
            p.standardOutput = output; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
            var result: URL?
            do {
                try p.run(); let data = output.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
                if p.terminationStatus == 0, let text = String(data:data,encoding:.utf8)?.trimmingCharacters(in:.whitespacesAndNewlines),
                   let url = URL(string:text), url.scheme == "http", url.host == "127.0.0.1", url.port == 18765, url.fragment?.hasPrefix("token=") == true { result = url }
            } catch { /* No raw process output/credential is logged. */ }
            DispatchQueue.main.async {
                guard let self = self else { return }; self.connecting = false
                if let url = result { self.web.load(URLRequest(url:url)) }
                else { self.placeholder.stringValue = "本机服务未就绪。请查看私有日志，或按 ⌘R 重连；不会关闭网络防护。" }
            }
        }
    }

    func webView(_ webView: WKWebView,didFinish navigation: WKNavigation!) { placeholder.isHidden = true }
    func webView(_ webView: WKWebView,didFailProvisionalNavigation navigation: WKNavigation!,withError error: Error) {
        placeholder.isHidden = false; placeholder.stringValue = "本机界面加载失败，按 ⌘R 重新连接。"
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        cancelInitialization(); placeholder.isHidden = false; placeholder.stringValue = "页面进程已退出。按 ⌘R 重连；不会重试任何 VM 操作。"
    }
    func webView(_ webView: WKWebView,decidePolicyFor navigationAction: WKNavigationAction,decisionHandler:@escaping(WKNavigationActionPolicy)->Void) {
        guard let u = navigationAction.request.url,u.scheme == "http",u.host == "127.0.0.1",u.port == 18765 else { decisionHandler(.cancel);return }
        decisionHandler(.allow)
    }

    private func ownedJSON(_ url: URL) throws -> [String:Any] {
        guard url.resolvingSymlinksInPath().path == url.path else { throw NSError(domain:"PrivatePath",code:1) }
        let attributes = try FileManager.default.attributesOfItem(atPath:url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              ((attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0o777) & 0o077 == 0,
              ((attributes[.size] as? NSNumber)?.intValue ?? Int.max) <= 1048576 else { throw NSError(domain:"PrivateFile",code:1) }
        guard let d = try JSONSerialization.jsonObject(with:Data(contentsOf:url)) as? [String:Any] else { throw NSError(domain:"PrivateJSON",code:1) }
        return d
    }

    private func validateManagedVM(_ name: String) throws {
        guard !name.isEmpty,name.count <= 64,name == name.trimmingCharacters(in:.whitespacesAndNewlines),
              !name.hasPrefix("."),!name.hasPrefix("-"),name.unicodeScalars.allSatisfy({CharacterSet.alphanumerics.contains($0) || " _-".unicodeScalars.contains($0)}) else { throw NSError(domain:"VMName",code:1) }
        let state = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/GoldVMManager",isDirectory:true)
        let r = try ownedJSON(state.appendingPathComponent("registry.json"))
        guard let vms = r["vms"] as? [String:[String:Any]],let item = vms[name],let id = item["environment_id"] as? String,
              id.range(of:"^[0-9a-f]{32}$",options:.regularExpression) != nil else { throw NSError(domain:"VMRegistry",code:1) }
        let m = try ownedJSON(state.appendingPathComponent("environments/\(id)/environment.json"))
        guard m["vm_name"] as? String == name,m["setup_active"] as? Bool == true else { throw NSError(domain:"VMEnvironment",code:1) }
    }

    func userContentController(_ userContentController: WKUserContentController,didReceive message: WKScriptMessage) {
        guard message.name == "startGuestInitialization",message.frameInfo.isMainFrame,
              let u = message.frameInfo.request.url,u.scheme == "http",u.host == "127.0.0.1",u.port == 18765,
              let body = message.body as? [String:Any],Set(body.keys) == Set(["vm_id","setup_profile"]),
              let vm = body["vm_id"] as? String,var profileObject = body["setup_profile"] as? [String:Any] else { return }
        guard initialization == nil else { notice("已有初始化正在运行，请先停止或等待完成。");return }
        let keys:Set<String> = ["version","language","country","timezone","location_services","skip_migration","skip_apple_account","share_analytics"]
        guard Set(profileObject.keys) == keys else { notice("初始化模板无效；此桥接不接收密码。");return }
        do {
            try validateManagedVM(vm)
            profileObject["allow_license_agreement"] = false
            let profile = try JSONDecoder().decode(GuestInitializationDriver.Profile.self,from:JSONSerialization.data(withJSONObject:profileObject))
            guard profile.language == "en-US" else { notice("当前自动点击引擎仅支持英语（美国）。其他语言模板可保存，但尚不能宣称自动初始化；未输入任何凭据。");return }
            let accessibility=AXIsProcessTrusted(),screenRecording=CGPreflightScreenCaptureAccess()
            guard accessibility,screenRecording else {
                publish(vm:vm,phase:"permissions",code:accessibility ? "screen_recording_permission_required" : (screenRecording ? "accessibility_permission_required" : "both_permissions_required"))
                permissionNotice();return
            }
            publish(vm:vm,phase:"waiting",code:"native_secure_form_opened")
            secureInitialization(vm:vm,profile:profile)
        } catch { notice("未能验证所选 VM 或模板，未打开凭据表单，也未操作客机。");return }
    }

    @objc private func checkInitializationPermissions() { permissionNotice() }
    private func permissionNotice() {
        let accessibility=AXIsProcessTrusted(),screenRecording=CGPreflightScreenCaptureAccess()
        let a=NSAlert();a.messageText="Gold VM 管理器 · 当前进程权限自检"
        a.informativeText="辅助功能：\(accessibility ? "已生效" : "未生效")\n屏幕录制：\(screenRecording ? "已生效" : "未生效")\n\n结果来自管理器当前进程自己的系统 API，不使用 DSH／终端的授权代替。未打开密码表单、未操作 VM，也不会修改权限数据库。屏录仅用于客机画面识别，不采集麦克风。"
        if accessibility && screenRecording {a.addButton(withTitle:"知道了");a.beginSheetModal(for:window,completionHandler:nil);return}
        a.addButton(withTitle:"请求屏幕录制授权");a.addButton(withTitle:"打开屏幕录制设置");a.addButton(withTitle:"打开辅助功能设置");a.addButton(withTitle:"取消")
        a.beginSheetModal(for:window){[weak self] response in
            if response == .alertFirstButtonReturn {
                // User-initiated, public TCC request from THIS App. No capture,
                // database edit, permission bypass, or private field access.
                let allowed=CGRequestScreenCaptureAccess()
                self?.notice(allowed ? "屏录请求已获准。请退出并重新打开管理器，然后再自检；VM 不需关闭。" : "屏录尚未生效。请在系统提示／隐私与安全中为当前 Gold VM 管理器本人授权，再重开管理器自检；不要改其他应用权限。")
            } else if response == .alertSecondButtonReturn {NSWorkspace.shared.open(URL(string:"x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture")!)}
            else if response == .alertThirdButtonReturn {NSWorkspace.shared.open(URL(string:"x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!)}
        }
    }

    private func secureInitialization(vm: String,profile: GuestInitializationDriver.Profile) {
        let alert = NSAlert();alert.messageText = "自动初始化 \(vm) · 本机安全输入"
        alert.informativeText = "仅用于全新 macOS 首次设置。已有账户或锁屏会停止，不会猜密码。凭据只在本机内存使用，不交给网页、模型、日志或命令行。自动化时请保持这台 VM 在前台且勿操作键鼠；未知页面会停止。当前仅英语美国可自动操作，抵达桌面仍需应用/验收时区等配置。"
        alert.addButton(withTitle:"开始自动初始化");alert.addButton(withTitle:"取消")
        let view = NSView(frame:NSRect(x:0,y:0,width:460,height:255))
        func label(_ text:String,_ y:CGFloat) { let f=NSTextField(labelWithString:text);f.frame=NSRect(x:0,y:y,width:460,height:20);view.addSubview(f) }
        func field(_ f:NSTextField,_ y:CGFloat) { f.frame=NSRect(x:0,y:y,width:460,height:26);view.addSubview(f) }
        let fullname=NSTextField(),username=NSTextField(),password=NSSecureTextField(),confirm=NSSecureTextField()
        fullname.placeholderString="显示名（英文/ASCII）";username.placeholderString="账户短名：小写字母、数字、下划线"
        password.placeholderString="客机密码（本机私密）";confirm.placeholderString="再次输入密码"
        label("账户显示名",230);field(fullname,203);label("本地管理员账户短名",178);field(username,151)
        label("密码与确认（4–128个ASCII字符；建议8位以上）",125);field(password,98);field(confirm,64)
        let terms=NSButton(checkboxWithTitle:"我已阅读并授权同意 macOS 软件许可条款",target:nil,action:nil)
        terms.frame=NSRect(x:0,y:25,width:460,height:25);terms.state = .off;view.addSubview(terms)
        alert.accessoryView=view
        alert.beginSheetModal(for:window) { [weak self] response in
            guard let self=self else{return}
            defer { password.stringValue="";confirm.stringValue="" }
            guard response == .alertFirstButtonReturn else{return}
            guard password.stringValue == confirm.stringValue,!password.stringValue.isEmpty else { self.notice("两次密码不一致或为空。未操作客机，请重新打开安全输入。");return }
            let ascii: (String)->Bool = { !$0.isEmpty && $0.unicodeScalars.allSatisfy{(32...126).contains(Int($0.value))} }
            guard ascii(fullname.stringValue),username.stringValue.range(of:"^[a-z][a-z0-9_]{0,31}$",options:.regularExpression) != nil,
                  ascii(password.stringValue),(4...128).contains(password.stringValue.count),password.stringValue == password.stringValue.trimmingCharacters(in:.whitespacesAndNewlines) else { self.notice("当前物理键盘自动化只支持上述 ASCII 名称/密码规则，未操作客机。");return }
            var chosen = profile;chosen.allow_license_agreement = terms.state == .on
            let secret=GuestInitializationDriver.Credentials(fullname:fullname.stringValue,username:username.stringValue,password:password.stringValue)
            let driver=GuestInitializationDriver();self.credentials=secret;self.initialization=driver
            self.powerActivity=ProcessInfo.processInfo.beginActivity(options:[.userInitiated,.idleDisplaySleepDisabled],reason:"用户请求的 VM 前端初始化")
            self.publish(vm:vm,phase:"starting",code:"local_secure_input_accepted")
            self.prepareVMWindow(vm)
            driver.start(vmName:vm,profile:chosen,credentials:secret,status:{[weak self] phase,code in self?.publish(vm:vm,phase:phase,code:code)},completion:{[weak self] result in
                secret.clear();self?.credentials=nil;self?.initialization=nil
                if let activity=self?.powerActivity {ProcessInfo.processInfo.endActivity(activity);self?.powerActivity=nil}
                self?.publish(vm:vm,phase:"stopped",code:result.code)
                self?.notice("初始化结果：\(result.code)。这不是网络、软件或时区已全部验收的声明；未知/未支持步骤请勿盲点重试。")
            })
        }
    }

    private func prepareVMWindow(_ vm:String) {
        let tartPath=FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/tart.app/Contents/MacOS/tart").path
        let apps=NSWorkspace.shared.runningApplications.filter{$0.executableURL?.path == tartPath}
        let ids=Set(apps.map{Int($0.processIdentifier)})
        let windows=CGWindowListCopyWindowInfo([.optionAll,.excludeDesktopElements],kCGNullWindowID) as? [[String:Any]] ?? []
        let matches=windows.filter{ids.contains($0[kCGWindowOwnerPID as String] as? Int ?? -1) && ($0[kCGWindowName as String] as? String)==vm}
        guard matches.count==1,let pid=matches[0][kCGWindowOwnerPID as String] as? Int,let app=apps.first(where:{Int($0.processIdentifier)==pid}) else{return}
        // The user explicitly requested initialization; place only this VM fully
        // inside one display before the driver snapshots its immutable bounds.
        let root=AXUIElementCreateApplication(pid_t(pid));var raw:CFTypeRef?
        if AXUIElementCopyAttributeValue(root,kAXWindowsAttribute as CFString,&raw) == .success,let list=raw as? [AXUIElement] {
            for w in list {
                var title:CFTypeRef?;AXUIElementCopyAttributeValue(w,kAXTitleAttribute as CFString,&title)
                guard title as? String == vm else{continue}
                let bounds=CGDisplayBounds(CGMainDisplayID());var position=CGPoint(x:bounds.minX+25,y:bounds.minY+65)
                var size=CGSize(width:min(1200,bounds.width-50),height:min(850,bounds.height-110))
                if let p=AXValueCreate(.cgPoint,&position){_=AXUIElementSetAttributeValue(w,kAXPositionAttribute as CFString,p)}
                if let s=AXValueCreate(.cgSize,&size){_=AXUIElementSetAttributeValue(w,kAXSizeAttribute as CFString,s)}
            }
        }
        app.unhide();_=app.activate(options:[.activateAllWindows])
    }

    private func publish(vm:String,phase:String,code:String) {
        guard let data=try? JSONSerialization.data(withJSONObject:["vm":vm,"phase":phase,"code":code]),let json=String(data:data,encoding:.utf8) else{return}
        web.evaluateJavaScript("window.dispatchEvent(new CustomEvent('gold-initialization-status',{detail:"+json+"}));",completionHandler:nil)
    }
    private func notice(_ text:String) { let a=NSAlert();a.messageText="Gold VM Manager";a.informativeText=text;a.addButton(withTitle:"知道了");a.beginSheetModal(for:window,completionHandler:nil) }
    @objc func cancelInitialization() { initialization?.cancel();credentials?.clear();credentials=nil;initialization=nil;if let activity=powerActivity{ProcessInfo.processInfo.endActivity(activity);powerActivity=nil} }
    @objc func reloadInterface() { cancelInitialization();connect() }
    func applicationWillTerminate(_ notification:Notification) { cancelInitialization() }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender:NSApplication)->Bool { true }
    func applicationShouldHandleReopen(_ sender:NSApplication,hasVisibleWindows flag:Bool)->Bool { window.makeKeyAndOrderFront(nil);return true }
}

@main
struct GoldManagerApp {
    @MainActor static func main() {
        let app=NSApplication.shared,delegate=Delegate();app.delegate=delegate;app.setActivationPolicy(.regular)
        withExtendedLifetime(delegate){app.run()}
    }
}
