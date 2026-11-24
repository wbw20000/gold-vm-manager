/* Explicit new-VM preinstall UI. No storage, subscriptions, host profile reads or automatic boot. */
(function (root, factory) {
  'use strict';
  const exported = factory();
  if (typeof module === 'object' && module.exports) module.exports = exported;
  else root.GoldPreinstall = exported;
})(typeof window === 'object' ? window : globalThis, function () {
  'use strict';
  const MAX_BYTES = 256 * 1024;
  const PROTOCOLS = ['tuic', 'vless', 'trojan', 'ss', 'hysteria2'];
  const APPS = ['CCBaga-A.app', 'CCBaga-B.app', 'Clash Verge.app', 'Claude.app'];
  const CIPHERS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305'];
  const WARNINGS = {
    'Uploaded routing rules were replaced by MATCH,PROXY.': '原路由规则将替换为固定的代理路由。',
    'Uploaded DNS settings were replaced by tunneled guest DNS.': '原 DNS 设置将替换为经代理访问的客机 DNS。',
    'Uploaded TUN settings were replaced by owned guest TUN settings.': '原 TUN 设置将替换为受控客机 TUN。',
    'Uploaded proxy groups were replaced by the owned PROXY selector.': '原代理组将替换为受控的 PROXY 选择器。',
    'Uploaded controller settings and credentials were not adopted.': '不会沿用原控制接口或其凭据。',
    'Uploaded general settings were replaced by owned guest policy.': '原通用设置将替换为固定保护策略。',
    'Domain endpoints were pinned to validated public IPv4 addresses.': '域名已显式解析并固定为经过校验的公网 IPv4。',
    'Submitted node names were replaced by generated private identifiers.': '节点名称将替换为中性私有编号。',
  };
  function need(ok, message) { if (!ok) throw new Error(message); }
  function text(value) { return typeof value === 'string' ? value : ''; }
  function bytes(value) { return new TextEncoder().encode(value).length; }
  function integer(value, low, high, label) {
    need(/^\d+$/.test(String(value)), `${label}须为整数。`);
    const n = Number(value);
    need(Number.isSafeInteger(n) && n >= low && n <= high, `${label}超出允许范围。`);
    return n;
  }
  const DISK_MIN = 30, DISK_MAX = 1024;
  const diskRange = `${DISK_MIN}–${DISK_MAX} GiB`;
  const diskError = `磁盘容量无效：请输入 ${diskRange} 范围内的整数。`;
  function validDisk(value) {
    return /^\d+$/.test(String(value)) && Number(value) >= DISK_MIN && Number(value) <= DISK_MAX;
  }
  function secret(value, label) {
    need(typeof value === 'string' && value.length > 0 && value.length <= 4096 && !/[\x00-\x1f\x7f]/.test(value), `请填写有效的${label}。`);
    return value; // Never trim passwords or interpolate submitted text into errors.
  }
  function endpoint(server, allowResolve) {
    need(server.length > 0 && server.length <= 253 && !/[\s/:\\@?#\[\]]/.test(server), '服务器仅支持公网 IPv4，或明确授权解析的域名；不支持 IPv6 或 URL。');
    if (/^[\d.]+$/.test(server)) {
      const parts = server.split('.');
      need(parts.length === 4 && parts.every(v => /^(0|[1-9]\d{0,2})$/.test(v) && Number(v) <= 255), 'IPv4 地址格式无效。');
      const [a, b, c] = parts.map(Number);
      need(a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 169 && b === 254) &&
        !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && (b === 168 || b === 0 || b === 88 && c === 99)) &&
        !(a === 100 && b >= 64 && b <= 127) && !(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) &&
        !(a === 203 && b === 0 && c === 113), '服务器必须是公网单播 IPv4；本机、内网和文档地址不可用。');
    } else {
      need(allowResolve === true, '域名服务器需要单独勾选授权 DNS 解析，或改用公网 IPv4。');
      need(server.includes('.') && server.split('.').every(v => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(v)), '服务器域名格式无效。');
    }
    return server;
  }
  function fieldSubmission(v, allowResolve) {
    const kind = v.protocol;
    need(PROTOCOLS.includes(kind), '不支持该节点协议。');
    const node = { type: kind, server: endpoint(text(v.server).trim(), allowResolve), port: integer(v.port, 1, 65535, '端口'), udp: v.udp !== false };
    need(node.port !== 53, '节点端口 53 不符合固定保护网络策略。');
    if (text(v.nodeName).trim()) node.name = secret(v.nodeName.trim(), '节点名称');
    if (kind === 'tuic' || kind === 'vless') {
      need(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(text(v.uuid)) && /[1-9a-f]/i.test(v.uuid), '请填写非零、标准格式的 UUID。');
      node.uuid = v.uuid;
    }
    if (kind !== 'vless') node.password = secret(v.password, '密码');
    if (kind === 'ss') {
      need(CIPHERS.includes(v.cipher), 'Shadowsocks 仅支持列出的三种 AEAD 加密。');
      node.cipher = v.cipher;
    } else {
      node['skip-cert-verify'] = false;
      if (text(v.sni).trim()) node[kind === 'vless' ? 'servername' : 'sni'] = v.sni.trim();
      if (text(v.alpn).trim()) {
        const alpn = v.alpn.split(',').map(s => s.trim());
        need(alpn.length <= 8 && alpn.every(s => /^[A-Za-z0-9./_-]{1,32}$/.test(s)), 'ALPN 请使用逗号分隔的有效协议名称。');
        node.alpn = alpn;
      }
    }
    if (kind === 'tuic') {
      node['disable-sni'] = false;
      if (v.congestion) { need(['cubic', 'new_reno', 'bbr'].includes(v.congestion), 'TUIC 拥塞控制选项无效。'); node['congestion-controller'] = v.congestion; }
      if (v.relay) { need(['native', 'quic'].includes(v.relay), 'TUIC UDP 中继选项无效。'); node['udp-relay-mode'] = v.relay; }
    }
    if (kind === 'vless' || kind === 'trojan') {
      node.tls = true; node.network = 'tcp';
      if (v.fingerprint) { need(['chrome', 'firefox', 'safari', 'ios', 'android', 'edge'].includes(v.fingerprint), 'TLS 指纹选项无效。'); node['client-fingerprint'] = v.fingerprint; }
    }
    if (kind === 'vless') {
      need(['tls', 'reality'].includes(v.security), 'VLESS 只支持 TLS 或 Reality。');
      if (v.flow) { need(v.flow === 'xtls-rprx-vision', 'VLESS flow 不支持。'); node.flow = v.flow; }
      if (v.security === 'reality') {
        need(/^[A-Za-z0-9_-]{43}$/.test(text(v.realityKey)), 'Reality 公钥须为 43 字符的 URL-safe Base64。');
        need(/^(?:[0-9a-f]{2}){0,8}$/i.test(text(v.shortId)), 'Reality short-id 须为 0–16 个偶数位十六进制字符。');
        node['reality-opts'] = { 'public-key': v.realityKey, 'short-id': text(v.shortId) };
      }
    }
    if (kind === 'hysteria2') {
      for (const key of ['up', 'down']) if (text(v[key])) node[key] = integer(v[key], 1, 100000, key === 'up' ? '上行速率' : '下行速率');
      need(!v.obfs || v.obfs === 'salamander', 'Hysteria2 仅支持 salamander 混淆。');
      if (v.obfs === 'salamander') { node.obfs = 'salamander'; node['obfs-password'] = secret(v.obfsPassword, '混淆密码'); }
    }
    return { input_mode: 'fields', nodes: [node] };
  }
  function nodeSources(context) {
    const names = Array.isArray(context?.nodeSources) ? context.nodeSources : [];
    return [...new Set(names.filter(n => typeof n === 'string' && n.length >= 1 && n.length <= 64))].slice(0, 64);
  }
  function submission(v) {
    if (v.mode === 'vm') {
      need(typeof v.nodeSource === 'string' && Array.isArray(v.sources) && v.sources.includes(v.nodeSource), '请选择一台保存了节点配置的 VM。');
      return { input_mode: 'vm', vm: v.nodeSource };
    }
    if (v.mode === 'fields') return fieldSubmission(v, v.allowResolve);
    need(v.mode === 'yaml', '请选择参数或本地 YAML 路径。');
    const path = text(v.yamlPath);
    need(path.length <= 4096 && path === path.trim() && path.startsWith('/') && !/[\x00-\x1f\x7f]/.test(path) &&
      path.slice(1).split('/').every(part => part && part !== '.' && part !== '..') && /\.ya?ml$/i.test(path), '请填写指向 .yaml 或 .yml 文件的规范本地绝对路径。');
    return { input_mode: 'yaml_path', path };
  }
  function vpnConsentFields(validated, now) {
    need(validated && /^[0-9a-f]{32}$/.test(validated.id) && validated.expires > now, '节点校验已失效，请重新校验。');
    return { vpn_configuration_id: validated.id, acknowledge_network_policy: true,
      ...(validated.normalization ? { acknowledge_normalization: true } : {}) };
  }
  function creationFields(v, context) {
    need(context.connected && !context.active, '本机服务不可用或已有任务，请先刷新状态。');
    const name = text(v.name);
    need(name.length >= 1 && name.length <= 64 && name === name.trim() && name.normalize('NFC') === name && /^[\p{L}\p{N} _-]+$/u.test(name) && !/^[.-]/.test(name), '请填写有效的新 VM 名称；不得使用已有名称。');
    need(!(context.names || []).some(n => String(n).normalize('NFC').toLowerCase() === name.toLowerCase()), '已有同名 VM；一键预装只能创建新名字，不能重建或覆盖。');
    const cpu = integer(v.cpu, 2, Number(context.host?.cpu_count) || 1024, 'CPU');
    const memory = integer(v.memory, 4, Number(context.host?.memory_gib) || 1024, '内存');
    need(validDisk(v.disk), diskError);
    const disk = Number(v.disk);
    need(v.imageMode === 'reviewed' || v.imageMode === 'local', '恢复镜像来源无效。');
    const ipsw = v.imageMode === 'reviewed' ? 'reviewed' : text(v.ipsw);
    need(ipsw === 'reviewed' || (ipsw.startsWith('/') && !ipsw.startsWith('//') && !/[\x00-\x1f\x7f]/.test(ipsw) && !ipsw.split('/').includes('..') && /\.ipsw$/i.test(ipsw)), '本地 IPSW 须为你信任的规范绝对路径。');
    const proxy = text(v.downloadProxy).trim();
    need(!proxy || (/^http:\/\/127\.0\.0\.1:[1-9]\d{0,4}$/.test(proxy) && Number(proxy.split(':').pop()) <= 65535), '下载代理只允许显式的 http://127.0.0.1:端口，不得带凭据或路径。');
    return { name, cpu, memory_gib: memory, disk_gib: disk, ipsw, download_loopback_proxy: proxy || null };
  }
  function createPayload(v, validated, context, now, confirmed) {
    need(confirmed === true, '请阅读说明并明确确认开始。');
    return { ...creationFields(v, context), acknowledge_preinstall: true,
      ...(v.deferVpn === true ? { defer_vpn: true } : vpnConsentFields(validated, now)) };
  }
  function isWaitingVpnJob(job) {
    return job?.mode === 'preinstall' && job.phase === 'awaiting_vpn_configuration' && job.published === false &&
      /^[0-9a-f]{32}$/.test(text(job.id)) && text(job.name).length > 0;
  }
  function sameWaitingJob(job, target) {
    return isWaitingVpnJob(job) && job.id === target.id && job.name === target.name;
  }
  function resumePayload(target, validated, context, now, confirmed) {
    need(confirmed === true, '请阅读说明并明确确认继续。');
    need(context.connected && target && sameWaitingJob(context.waitingJob, target), '待配置任务已变化，请刷新状态并从当前任务重新打开。');
    return { job_id: target.id, ...vpnConsentFields(validated, now) };
  }
  function validateResponse(result, now) {
    const s = result?.summary;
    need(result?.configuration_stored_privately === true && result.vpn_connected === false && /^[0-9a-f]{32}$/.test(text(result.configuration_id)) &&
      Number.isInteger(result.expires_in_seconds) && result.expires_in_seconds > 0 && s &&
      Number.isInteger(s.node_count) && s.node_count >= 1 && s.node_count <= 16 && Number.isInteger(s.endpoint_count) && s.endpoint_count >= 1 && s.endpoint_count <= 32 &&
      Array.isArray(s.protocols) && s.protocols.length > 0 && s.protocols.every(p => PROTOCOLS.includes(p)) && Array.isArray(s.warnings) && typeof s.normalization_required === 'boolean', '本机服务未返回有效的私有节点校验凭据。');
    return { id: result.configuration_id, expires: now + Math.min(3600, result.expires_in_seconds) * 1000, normalization: s.normalization_required };
  }
  function defaultSave(document, content, filename, mime) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = filename;
    document.body.append(link);
    try { link.click(); } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 0); }
  }

  function mount({ document, api, getContext, onBusy = () => {}, onQueued = async () => {}, clock = Date.now, saveExample }) {
    const controls = {}, rows = {}, allControls = [];
    let busy = false, revision = 0, validated = null, capabilities = null, requestUncertain = false;
    let resumeTarget = null, resumeStale = false, lastDefer = false, lastMode = 'yaml', sources = [];
    const node = (tag, cls, value) => { const n = document.createElement(tag); if (cls) n.className = cls; if (value !== undefined) n.textContent = String(value); return n; };
    const dialog = node('dialog', 'modal preinstall-modal'); dialog.id = 'preinstall-dialog'; dialog.setAttribute('aria-labelledby', 'preinstall-title');
    const form = node('form'); form.noValidate = true; form.setAttribute('autocomplete', 'off');
    const heading = node('div', 'modal-heading'), title = node('h2', '', '新建 VM 及预装软件'); title.id = 'preinstall-title';
    const close = node('button', 'icon-button preinstall-close', '×'); close.type = 'button'; close.setAttribute('aria-label', '关闭预装对话框');
    const description = node('p', 'modal-description');
    description.id = 'preinstall-description';
    heading.append(title, close); form.append(heading, description);
    const capabilityBox = node('section', 'preinstall-capabilities');
    capabilityBox.id = 'preinstall-capability-blockers'; capabilityBox.hidden = true;
    capabilityBox.setAttribute('aria-live', 'polite'); form.append(capabilityBox);
    const capabilityMessage = node('div');
    function action(label, handler, cls = 'button button-secondary') {
      const b = node('button', cls, label); b.type = 'button'; b.addEventListener('click', handler); allControls.push(b); return b;
    }
    const checkButton = action('重新检查', () => checkCapabilities(), 'text-button');
    checkButton.id = 'preinstall-check-capabilities'; capabilityBox.append(capabilityMessage, checkButton);
    function section(label) { const s = node('fieldset', 'preinstall-section'); s.append(node('legend', '', label)); form.append(s); return s; }
    function field(parent, key, label, options = {}) {
      const row = node('div', 'field'), caption = node('label', '', label);
      const input = node(options.choices ? 'select' : 'input');
      input.id = 'preinstall-' + key; caption.htmlFor = input.id; input.autocomplete = 'off'; input.spellcheck = false;
      if (options.choices) options.choices.forEach(([value, label]) => { const o = node('option', '', label); o.value = value; input.append(o); });
      else input.type = options.type || 'text';
      if (options.min !== undefined) input.min = String(options.min);
      if (options.max !== undefined) input.max = String(options.max);
      if (options.type === 'number') input.step = '1';
      if (options.placeholder) input.placeholder = options.placeholder;
      input.value = options.value !== undefined ? options.value : options.choices ? options.choices[0][0] : '';
      if (!options.choices) input.maxLength = options.maxLength || 4096;
      row.append(caption, input); if (options.note) row.append(node('small', '', options.note));
      parent.append(row); controls[key] = input; rows[key] = row; allControls.push(input); return input;
    }
    function check(parent, key, label, checked = false) {
      const row = node('label', 'checkbox-label'), input = node('input'); input.type = 'checkbox'; input.id = 'preinstall-' + key; input.checked = checked;
      row.append(input, node('span', '', label)); parent.append(row); controls[key] = input; rows[key] = row; allControls.push(input); return input;
    }
    const machine = section('1 · 全新系统与资源');
    field(machine, 'name', '新的 VM 名称', { maxLength: 64, placeholder: '必须为尚未使用的新名字' });
    const resourceGrid = node('div', 'preinstall-grid'); machine.append(resourceGrid);
    field(resourceGrid, 'cpu', 'CPU（vCPU）', { type: 'number', min: 2, value: '2' });
    field(resourceGrid, 'memory', '内存（GiB）', { type: 'number', min: 4, value: '4' });
    const disk = field(resourceGrid, 'disk', '磁盘（GiB）', { type: 'number', min: DISK_MIN, max: DISK_MAX, value: '50' });
    const diskFeedback = node('p', 'form-error', diskError); diskFeedback.id = 'preinstall-disk-error';
    diskFeedback.setAttribute('role', 'status'); rows.disk.append(diskFeedback);
    const diskNote = node('p', 'form-note', `磁盘可填 ${diskRange} 的整数，默认 50 GiB。较小的磁盘可能放不下 macOS 或后续系统更新。`);
    diskNote.id = 'preinstall-disk-note'; disk.setAttribute('aria-describedby', `${diskNote.id} ${diskFeedback.id}`); machine.append(diskNote);
    machine.append(node('p', 'form-note', '宿主空间示例：虚拟磁盘与安装材料在同一卷时，创建 30 GiB 磁盘，复用已缓存的默认镜像约需 42 GiB 可用空间；重新下载或导入镜像约需 62 GiB。不同卷分别检查，以安装时的实际可用空间为准。'));
    field(machine, 'imageMode', '系统镜像来源', { choices: [['reviewed', '经审核的固定 Apple 恢复镜像'], ['local', '我信任的本机 IPSW 绝对路径']] });
    const imageNote = node('p', 'form-note'); imageNote.id = 'preinstall-image-note'; imageNote.hidden = true; machine.append(imageNote);
    field(machine, 'ipsw', '可信本地 IPSW 路径', { placeholder: '/绝对路径/macOS.ipsw', note: '不上传镜像文件，不使用开发者证据路径；本机来源与完整性仍须后端校验。' });
    const downloadSettings = node('details', 'preinstall-download-settings');
    downloadSettings.id = 'preinstall-download-settings';
    const downloadSummary = node('summary', '', '高级下载设置');
    downloadSettings.append(downloadSummary);
    machine.append(downloadSettings);
    field(downloadSettings, 'downloadProxy', '本机下载代理（可选）', { placeholder: '留空直接下载，或 http://127.0.0.1:端口', note: '仅影响系统镜像及安装包下载，不是客机 VPN；不接收账号密码。' });
    const vpn = section('2 · Clash / Mihomo 配置');
    check(vpn, 'deferVpn', '先不配置 VPN');
    const deferNote = node('p', 'form-note', '系统与应用装好后会暂停，等待你回来配置 VPN。此时 VM 不会发布或开机，也不会配置客机网络。');
    deferNote.id = 'preinstall-defer-note'; vpn.append(deferNote);
    const vpnInputs = node('div'); vpnInputs.id = 'preinstall-vpn-inputs'; vpn.append(vpnInputs);
    field(vpnInputs, 'nodeSource', '节点来源', { choices: [['', '填写新的节点']], note: '沿用时使用那台 VM 构建时校验过的同一组节点和端点，不用再填 YAML；那台 VM 不受影响。' });
    const yamlPanel = node('div', 'preinstall-yaml');
    yamlPanel.id = 'preinstall-yaml-panel'; vpnInputs.append(yamlPanel);
    yamlPanel.append(node('p', 'form-note', '可下载模板并在本机填好，再填写文件的绝对路径。用在线模型整理时只给占位值，真实密码、UUID 和订阅链接留在本机。'));
    const exampleYaml = action('下载 YAML 填写模板', () => downloadExample('yaml'), 'text-button');
    const exampleRow = node('div', 'preinstall-actions'); exampleRow.append(exampleYaml); yamlPanel.append(exampleRow);
    field(yamlPanel, 'yamlPath', '本地 Clash YAML 绝对路径', { placeholder: '/绝对路径/clash.yaml', note: '只读取你指定的本机文件（≤ 256 KiB，最多 16 个节点）；不上传文件，不支持订阅链接。' });
    const manualSettings = node('details', 'preinstall-disclosure');
    manualSettings.id = 'preinstall-manual-fields';
    const manualSummary = node('summary', '', '手工填写'); manualSettings.append(manualSummary); vpnInputs.append(manualSettings);
    const fieldsPanel = node('div', 'preinstall-node-fields'); manualSettings.append(fieldsPanel);
    fieldsPanel.append(node('p', 'form-note', '展开时使用下方的单节点表单；收起后回到本地 YAML 路径。'));
    field(fieldsPanel, 'protocol', '节点协议', { choices: PROTOCOLS.map(p => [p, p === 'ss' ? 'Shadowsocks（AEAD）' : p.toUpperCase()]) });
    field(fieldsPanel, 'nodeName', '节点名称（可留空）', { maxLength: 256, placeholder: '留空由服务生成中性编号' });
    field(fieldsPanel, 'server', '服务器 · 公网 IPv4 或显式解析的域名', { maxLength: 253, placeholder: '填写你自己的公网节点地址' });
    field(fieldsPanel, 'port', '端口（不支持 53）', { type: 'number', min: 1, max: 65535 });
    field(fieldsPanel, 'uuid', 'UUID', { type: 'password', maxLength: 36 });
    field(fieldsPanel, 'password', '节点密码', { type: 'password' });
    field(fieldsPanel, 'sni', 'TLS 服务器名称 / SNI（可选）', { maxLength: 253, note: '公网 IP 与证书域名不同时请明确填写；保持证书校验开启。' });
    field(fieldsPanel, 'alpn', 'ALPN（可选，逗号分隔）', { placeholder: '例如 h3；须与节点服务一致' });
    field(fieldsPanel, 'cipher', 'Shadowsocks AEAD 加密', { choices: CIPHERS.map(v => [v, v]) });
    field(fieldsPanel, 'congestion', 'TUIC 拥塞控制', { choices: [['', '沿用协议默认'], ['cubic', 'cubic'], ['new_reno', 'new_reno'], ['bbr', 'bbr']] });
    field(fieldsPanel, 'relay', 'TUIC UDP 中继', { choices: [['', '沿用协议默认'], ['native', 'native'], ['quic', 'quic']] });
    field(fieldsPanel, 'security', 'VLESS 安全层（固定 TCP）', { choices: [['tls', 'TLS'], ['reality', 'Reality']] });
    field(fieldsPanel, 'flow', 'VLESS flow', { choices: [['', '不指定'], ['xtls-rprx-vision', 'xtls-rprx-vision']] });
    field(fieldsPanel, 'fingerprint', 'TLS 客户端指纹', { choices: [['', '不指定（Reality 默认 chrome）'], ...['chrome', 'firefox', 'safari', 'ios', 'android', 'edge'].map(v => [v, v])] });
    field(fieldsPanel, 'realityKey', 'Reality public-key', { type: 'password', maxLength: 43 });
    field(fieldsPanel, 'shortId', 'Reality short-id（可为空）', { type: 'password', maxLength: 16 });
    field(fieldsPanel, 'up', 'Hysteria2 上行 Mbps（可选）', { type: 'number', min: 1, max: 100000 });
    field(fieldsPanel, 'down', 'Hysteria2 下行 Mbps（可选）', { type: 'number', min: 1, max: 100000 });
    field(fieldsPanel, 'obfs', 'Hysteria2 混淆', { choices: [['', '不启用'], ['salamander', 'salamander']] });
    field(fieldsPanel, 'obfsPassword', 'salamander 混淆密码', { type: 'password' });
    check(fieldsPanel, 'udp', '保留协议允许的 UDP 能力（不绕过端点保护）', true);
    const dnsSettings = node('details', 'preinstall-disclosure');
    dnsSettings.append(node('summary', '', '节点使用域名时的设置')); vpnInputs.append(dnsSettings);
    check(dnsSettings, 'allowResolve', '允许本机解析节点域名并固定到校验过的公网 IPv4。此操作不会连接 VPN。');
    const validateButton = action('校验并私有保存节点', () => validate(), 'button button-primary');
    validateButton.id = 'preinstall-validate'; vpnInputs.append(validateButton);
    const summary = node('section', 'preinstall-summary'); summary.id = 'preinstall-summary'; summary.setAttribute('aria-live', 'polite'); vpnInputs.append(summary);
    const consent = node('p', 'form-note');
    consent.id = 'preinstall-operation-note'; form.append(consent);
    const normalizationNotice = node('p', 'form-note', '本次配置需要归一化：请查看上方校验结果；点击确认也表示同意列出的变更。');
    normalizationNotice.id = 'preinstall-normalization-note'; normalizationNotice.hidden = true; form.append(normalizationNotice);
    const error = node('p', 'form-error'); error.id = 'preinstall-error'; error.hidden = true; error.setAttribute('role', 'alert'); form.append(error);
    const footer = node('div', 'modal-footer');
    const cancel = node('button', 'button button-secondary preinstall-close', '取消'); cancel.type = 'button';
    const submitButton = node('button', 'button button-primary', '同意并开始预装'); submitButton.type = 'button'; submitButton.id = 'preinstall-submit';
    submitButton.setAttribute('aria-describedby', 'preinstall-operation-note preinstall-normalization-note');
    footer.append(cancel, submitButton); form.append(footer); dialog.append(form); document.body.append(dialog);
    const defaults = Object.fromEntries(Object.entries(controls).map(([key, input]) => [key, input.type === 'checkbox' ? input.checked : input.value]));
    const vpnKeys = new Set(['nodeSource', 'yamlPath', 'protocol', 'nodeName', 'server', 'port', 'uuid', 'password', 'sni', 'alpn', 'cipher', 'congestion', 'relay', 'security', 'flow', 'fingerprint', 'realityKey', 'shortId', 'up', 'down', 'obfs', 'obfsPassword', 'udp', 'allowResolve']);
    const machineKeys = new Set(['name', 'cpu', 'memory', 'disk', 'imageMode', 'ipsw', 'downloadProxy']);
    const currentMode = () => controls.nodeSource.value ? 'vm' : manualSettings.open ? 'fields' : 'yaml';
    const deferred = () => !resumeTarget && controls.deferVpn.checked;
    function values(keys) {
      return Object.fromEntries([...keys].map(key => { const input = controls[key]; return [key, input.type === 'checkbox' ? input.checked : input.value]; }));
    }
    function resetControls(keys) {
      for (const key of keys) { const input = controls[key]; if (input.type === 'checkbox') input.checked = defaults[key]; else input.value = defaults[key]; }
    }
    function showError(message) { error.textContent = message; error.hidden = false; }
    function invalidate(message = '配置尚未校验；任何修改都需重新校验。') {
      revision += 1; validated = null; normalizationNotice.hidden = true;
      summary.replaceChildren(node('p', 'form-note', message));
    }
    function clearVpnInputs() {
      resetControls(vpnKeys);
      // With a VM to copy from, that is the starting choice: nothing to type again.
      controls.nodeSource.value = sources[0] || '';
      manualSettings.open = false; dnsSettings.open = false; lastMode = currentMode(); invalidate();
    }
    function syncSources(context) {
      const names = nodeSources(context);
      if (names.length === sources.length && names.every((name, i) => name === sources[i])) return;
      sources = names;
      const select = controls.nodeSource, kept = select.value;
      select.replaceChildren(...[['', '填写新的节点'], ...names.map(name => [name, `沿用「${name}」的节点`])].map(([value, label]) => {
        const option = node('option', '', label); option.value = value; return option;
      }));
      // A source that is gone cannot stay selected; the mode change that follows drops its validation.
      select.value = names.includes(kept) ? kept : '';
    }
    function syncInputMode() {
      const skip = deferred();
      if (lastDefer !== skip) { lastDefer = skip; clearVpnInputs(); }
      const mode = currentMode();
      if (lastMode !== mode) { lastMode = mode; invalidate('输入方式已切换，请重新校验。'); }
    }
    function canOperate(context) {
      return context.connected && (resumeTarget ? !resumeStale && sameWaitingJob(context.waitingJob, resumeTarget) : !context.active);
    }
    function finalPayload(context, confirmed) {
      return resumeTarget ? resumePayload(resumeTarget, validated, context, clock(), confirmed) :
        createPayload({ ...values(machineKeys), deferVpn: deferred() }, validated, context, clock(), confirmed);
    }
    function visibility() {
      const p = controls.protocol.value;
      const reuse = currentMode() === 'vm';
      rows.nodeSource.hidden = sources.length === 0;
      yamlPanel.hidden = reuse || manualSettings.open;
      manualSettings.hidden = reuse; dnsSettings.hidden = reuse;
      const local = controls.imageMode.value === 'local';
      rows.ipsw.hidden = !local;
      imageNote.hidden = capabilities?.imageCached !== true;
      imageNote.textContent = local ? '本机已有核验过的系统镜像，不必再选文件；再选一次会另存一份约 20 GB 的副本。'
        : '本机已有核验过的系统镜像：直接使用，不再下载，也不用选文件（每次构建仍会重新核对）。';
      const visible = { uuid: ['tuic', 'vless'].includes(p), password: p !== 'vless', sni: p !== 'ss', alpn: p !== 'ss', cipher: p === 'ss',
        congestion: p === 'tuic', relay: p === 'tuic', security: p === 'vless', flow: p === 'vless', fingerprint: ['vless', 'trojan'].includes(p),
        realityKey: p === 'vless' && controls.security.value === 'reality', shortId: p === 'vless' && controls.security.value === 'reality',
        up: p === 'hysteria2', down: p === 'hysteria2', obfs: p === 'hysteria2', obfsPassword: p === 'hysteria2' && controls.obfs.value === 'salamander' };
      Object.entries(visible).forEach(([key, shown]) => { rows[key].hidden = !shown; });
      normalizationNotice.hidden = !validated?.normalization;
    }
    function update() {
      const context = getContext();
      if (resumeTarget && !resumeStale && !sameWaitingJob(context.waitingJob, resumeTarget)) {
        resumeStale = true; clearVpnInputs();
        showError('待配置任务已变化，请关闭此窗口，刷新后从当前任务重新打开。');
      }
      syncSources(context);
      syncInputMode();
      if (validated && clock() >= validated.expires) invalidate('节点校验已过期，请重新校验。');
      visibility();
      validateButton.textContent = currentMode() === 'vm' ? `沿用并校验这组节点（来源：${controls.nodeSource.value}）` : '校验并私有保存节点';
      const resuming = resumeTarget !== null, skip = deferred();
      const unavailable = busy || !canOperate(context);
      machine.hidden = resuming;
      diskFeedback.hidden = resuming || validDisk(disk.value);
      disk.setAttribute('aria-invalid', String(!diskFeedback.hidden));
      rows.deferVpn.hidden = resuming;
      deferNote.hidden = !skip;
      vpnInputs.hidden = skip;
      title.textContent = resuming ? `继续配置 VPN · ${resumeTarget.name}` : '新建 VM 及预装软件';
      description.textContent = resuming ? '仅为这项已恢复系统、已下载应用的任务配置 VPN，沿用原资源，不重建也不自动开机。' :
        '仅创建新名字，不重建旧 VM，不自动首次开机。原始公开下载经固定版本、签名与完整性验证；不往客机磁盘写入任何东西。';
      const finalLabel = resuming ? '同意并继续配置 VPN' : skip ? '同意并开始预装（暂不配置 VPN）' : '同意并开始预装';
      const networkNote = '首次设置用普通网络，并挂一个只读文件夹，里面是 CCBaga A+B、Clash Verge、Claude Desktop 和节点配置：由你用 Finder 安装应用、在 Clash 导入节点。确认连上节点后标记首次设置完成，之后只走校验过的节点。';
      const installNote = '仅创建新 VM，不覆盖或自动开机。恢复全新 macOS，下载并核验 4 个应用。';
      consent.textContent = resuming ? `点击「${finalLabel}」将绑定这份节点配置并继续发布，不会重装或自动开机。${networkNote}` :
        `点击「${finalLabel}」${installNote}${skip ? '系统恢复后暂停；配置 VPN 之前不会发布或开机。' : networkNote}`;
      downloadSummary.textContent = controls.downloadProxy.value.trim() ? '高级下载设置（已填写代理）' : '高级下载设置';
      allControls.forEach(input => { input.disabled = busy; });
      for (const key of machineKeys) controls[key].disabled = busy || resuming;
      for (const key of vpnKeys) controls[key].disabled = unavailable || skip;
      controls.deferVpn.disabled = unavailable || resuming;
      validateButton.disabled = unavailable || skip || capabilities?.ready !== true;
      checkButton.disabled = unavailable;
      exampleYaml.disabled = unavailable || skip;
      close.disabled = busy; cancel.disabled = busy;
      let valid = false;
      try { finalPayload(context, true); valid = true; } catch (_) { /* Readiness only; do not expose input. */ }
      submitButton.disabled = unavailable || !valid || capabilities?.ready !== true || requestUncertain;
      submitButton.textContent = busy ? '正在处理，请稍候…' : finalLabel;
    }
    function reset() {
      resetControls(machineKeys); resetControls(['deferVpn']); syncSources(getContext()); clearVpnInputs();
      resumeTarget = null; resumeStale = false; lastDefer = false;
      downloadSettings.open = false;
      capabilities = null; requestUncertain = false; error.hidden = true; error.textContent = '';
      capabilityBox.hidden = true; capabilityMessage.replaceChildren();
    }
    function showCapabilityBlockers(reasons) {
      const list = node('ul');
      reasons.forEach(reason => list.append(node('li', '', reason)));
      capabilityMessage.replaceChildren(node('strong', 'preinstall-not-ready', resumeTarget ? '暂不能继续配置 VPN' : '暂不能开始预装'), list);
      capabilityBox.hidden = false;
    }
    async function checkCapabilities() {
      if (busy || !dialog.open || !canOperate(getContext())) return;
      busy = true; capabilities = null; capabilityBox.hidden = true; capabilityMessage.replaceChildren(); update();
      try {
        const result = await api('/api/preinstall/capabilities');
        if (!dialog.open || !canOperate(getContext())) return;
        const apps = Array.isArray(result.applications) ? result.applications : [];
        const complete = apps.length === APPS.length && APPS.every(name => apps.some(app => app?.name === name && typeof app.version === 'string'));
        capabilities = { ready: result.ready === true && complete, imageCached: result.restore_image_cached === true };
        if (!capabilities.ready) {
          const reasons = Array.isArray(result.checks) ? result.checks.filter(check => check?.ready === false)
            .map(check => text(check.message).trim().slice(0, 600)).filter(Boolean).slice(0, 8) : [];
          if (!complete) reasons.push('完整的 4 个应用及固定版本清单尚未确认。');
          showCapabilityBlockers(reasons.length ? reasons : ['本机前置检查未通过，请重新检查。']);
        }
      } catch (_) {
        if (dialog.open && canOperate(getContext())) showCapabilityBlockers(['无法确认本机预装能力，请确认管理器服务正常后重新检查。']);
      } finally { busy = false; update(); }
    }
    async function openDialog(target) {
      reset(); resumeTarget = target; update(); dialog.showModal();
      (target ? (sources.length ? controls.nodeSource : controls.yamlPath) : controls.name).focus();
      await checkCapabilities();
    }
    async function open() {
      const context = getContext();
      if (busy || dialog.open || !context.connected || context.active) return;
      await openDialog(null);
    }
    async function openResume(jobId) {
      const { connected, waitingJob } = getContext();
      if (busy || dialog.open || !connected || !isWaitingVpnJob(waitingJob) || waitingJob.id !== jobId) return;
      await openDialog({ id: waitingJob.id, name: waitingJob.name });
    }
    async function validate() {
      update();
      if (busy || validateButton.disabled || !dialog.open) return;
      let body;
      const mode = currentMode(), source = controls.nodeSource.value;
      // Copying a VM's nodes resolves nothing, whatever the hidden DNS box holds.
      try { const v = values(vpnKeys); body = { submission: submission({ ...v, mode, sources }), allow_resolve: mode !== 'vm' && v.allowResolve === true }; }
      catch (e) { showError(e.message); return; }
      invalidate('正在校验节点；此操作不会连接 VPN。');
      const sentRevision = revision;
      const stillValidating = () => {
        syncInputMode();
        return sentRevision === revision && dialog.open && canOperate(getContext());
      };
      busy = true; error.hidden = true; update();
      try {
        const result = await api('/api/preinstall/vpn/validate', { method: 'POST', body, timeout: 30000 });
        if (!stillValidating()) return;
        validated = validateResponse(result, clock());
        requestUncertain = false;
        const s = result.summary;
        const counts = `${s.node_count} 个节点 / ${s.endpoint_count} 个端点 · ${s.protocols.join('、')}`;
        summary.replaceChildren(node('strong', '', mode === 'vm' ? `已沿用「${source}」的 ${counts}` : `已私有保存 ${counts}`),
          node('p', '', mode === 'vm' ? '与那台 VM 是同一组节点和端点，已重新核对，未连接 VPN。改选节点来源后须重新校验。'
            : '仅通过格式与端点校验，未连接 VPN。最终确认只发送不透明配置编号；修改输入后须重新校验。'));
        const list = node('ul'); s.warnings.slice(0, 32).forEach(w => list.append(node('li', '', WARNINGS[w] || '另有固定策略变更，请重新核对输入支持范围。'))); summary.append(list);
      } catch (_) {
        if (!stillValidating()) return;
        invalidate('校验未完成，未获得可用的配置编号。');
        showError(mode === 'vm' ? '无法沿用这台 VM 的节点：它没有保存节点配置，或配置已被改动。请把「节点来源」改为「填写新的节点」。'
          : '节点校验失败。请核对本地 YAML 路径、文件大小、受支持字段及 DNS 授权；不会回显路径或凭据，也不会自动连接。');
      } finally { body = null; busy = false; update(); }
    }
    async function downloadExample(kind) {
      update();
      if (exampleYaml.disabled || !dialog.open || !['yaml', 'fields'].includes(kind)) return;
      busy = true; error.hidden = true; update();
      try {
        const result = await api('/api/preinstall/examples');
        need(typeof result.yaml === 'string' && result.fields && typeof result.fields === 'object', '样例不可用。');
        const content = kind === 'yaml' ? result.yaml : JSON.stringify(result.fields, null, 2) + '\n';
        need(bytes(content) <= MAX_BYTES, '样例过大。');
        const filename = 'preinstall-node-example.' + (kind === 'yaml' ? 'yaml' : 'json');
        const mime = kind === 'yaml' ? 'text/yaml;charset=utf-8' : 'application/json;charset=utf-8';
        if (saveExample) saveExample(content, filename, mime); else defaultSave(document, content, filename, mime);
      } catch (_) { showError('固定非秘密样例暂不可用；不会下载你的实际配置。'); }
      finally { busy = false; update(); }
    }
    async function submit() {
      update(); if (busy || submitButton.disabled || !dialog.open) return;
      let body;
      try { body = finalPayload(getContext(), true); }
      catch (e) { showError(e.message); return; }
      const target = resumeTarget, skip = deferred();
      busy = true; error.hidden = true; onBusy(true); update();
      try {
        const result = await api(target ? '/api/preinstall/resume' : '/api/preinstall/create', { method: 'POST', body, timeout: 30000 });
        const job = result.job || result;
        need(typeof job.id === 'string' && typeof job.phase === 'string' &&
          (!target || (job.id === target.id && job.name === target.name && job.phase === 'vpn_resume_queued')), '请求结果尚未确认。');
        // Clear all input secrets before handing off the accepted job to polling.
        reset(); await onQueued(job, { resumed: target !== null, deferred: skip }); dialog.close();
      } catch (_) {
        invalidate('请求结果尚未确认，此配置编号不可再次直接提交。'); requestUncertain = true;
        showError(skip ? '请求结果未确认，请关闭此窗口并刷新任务状态，不要重复创建；本页不会自动重试。' :
          '请求结果未确认，请先刷新任务状态，不要重复提交。若服务拒绝了请求，修正条件后需重新校验节点；本页不会自动重试。');
      } finally { body = null; busy = false; onBusy(false); update(); }
    }
    Object.entries(controls).forEach(([key, input]) => {
      const changed = () => { if (vpnKeys.has(key)) invalidate(); if (!resumeStale) error.hidden = true; update(); };
      input.addEventListener('input', changed); input.addEventListener('change', changed);
    });
    close.addEventListener('click', () => { if (!busy) dialog.close(); });
    cancel.addEventListener('click', () => { if (!busy) dialog.close(); });
    dialog.addEventListener('cancel', event => { if (busy) event.preventDefault(); });
    dialog.addEventListener('close', () => { reset(); update(); });
    manualSummary.addEventListener('click', event => { if (busy) event.preventDefault(); });
    manualSettings.addEventListener('toggle', update);
    form.addEventListener('submit', event => event.preventDefault());
    submitButton.addEventListener('click', submit);
    invalidate(); update();
    return { open, openResume, update, validate, downloadExample, checkCapabilities };
  }
  return { mount, fieldSubmission, submission, nodeSources, createPayload, resumePayload, isWaitingVpnJob, validateResponse, MAX_BYTES, PROTOCOLS, APPS };
});
