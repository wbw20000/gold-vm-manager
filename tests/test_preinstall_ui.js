// Pure Node fixture DOM/handler tests. No server, browser, host config, VM or network.
// Run: node --test tests/test_preinstall_ui.js tests/test_offline_ui.js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ui = require('../static/preinstall.js');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'static/preinstall.js'), 'utf8');
const appSource = fs.readFileSync(path.join(root, 'static/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'static/index.html'), 'utf8');
const ID = 'a'.repeat(32);
const JOB_ID = 'b'.repeat(32);
const YAML_PATH = '/Users/operator/Private VPN/clash.yaml';
const UUID = '11111111-2222-4333-8444-555555555555';
const REALITY_KEY = Buffer.alloc(32, 1).toString('base64url');

function fixtureDOM() {
  const ids = new Map();
  class Element {
    constructor(tag) {
      this.tagName = tag.toUpperCase(); this.children = []; this.listeners = new Map();
      this.attributes = {}; this.value = ''; this.checked = false; this.disabled = false;
      this.hidden = false; this.open = false; this.type = ''; this._text = ''; this.parentNode = null;
    }
    set id(value) { this._id = value; ids.set(value, this); }
    get id() { return this._id; }
    set textContent(value) { this._text = String(value); this.children = []; }
    get textContent() { return this._text + this.children.map(n => n.textContent).join(''); }
    setAttribute(name, value) { this.attributes[name] = value; }
    append(...items) { for (const item of items) { item.parentNode = this; this.children.push(item); } }
    replaceChildren(...items) { this._text = ''; this.children = []; this.append(...items); }
    addEventListener(name, callback) { if (!this.listeners.has(name)) this.listeners.set(name, []); this.listeners.get(name).push(callback); }
    async fire(name) { const event = { target: this, preventDefault() { this.prevented = true; } }; await Promise.all((this.listeners.get(name) || []).map(fn => fn(event))); return event; }
    focus() {}
    showModal() { this.open = true; }
    close() { this.open = false; for (const fn of this.listeners.get('close') || []) fn({}); }
    remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(n => n !== this); }
    click() { return this.fire('click'); }
  }
  const document = { createElement: tag => new Element(tag), getElementById: id => ids.get(id), body: new Element('body') };
  return document;
}
function capabilities() { return { ok: true, ready: true, checks: [{ id: 'native', ready: true, message: '已审核原生工具' }],
  supported_tuples: [['Darwin', 'arm64', '26.6.2']], applications: ui.APPS.map(name => ({ name, version: '1.2.3' })), limitations: ['不自动首次开机'] }; }
function validated(normalization = false) { return { ok: true, configuration_id: ID, configuration_stored_privately: true,
  vpn_connected: false, expires_in_seconds: 3600, summary: { node_count: 1, endpoint_count: 1, protocols: ['tuic'],
    warnings: normalization ? ['Uploaded routing rules were replaced by MATCH,PROXY.'] : [], normalization_required: normalization } }; }
function waitingJob(overrides = {}) {
  return { id: JOB_ID, mode: 'preinstall', phase: 'awaiting_vpn_configuration', name: 'new VM', published: false, ...overrides };
}
function fixture() {
  const document = fixtureDOM(), calls = [], downloads = [], busyEvents = [], jobs = [], queueModes = [];
  const context = { connected: true, active: false, waitingJob: null, names: ['existing VM'], host: { cpu_count: 10, memory_gib: 64 } };
  let now = 1000, submitting = false;
  const handlers = {
    '/api/preinstall/capabilities': () => capabilities(),
    '/api/preinstall/vpn/validate': () => validated(),
    '/api/preinstall/examples': () => ({ ok: true, yaml: 'proxies: [] # public example only\n', fields: { input_mode: 'fields', nodes: [] } }),
    '/api/preinstall/create': () => ({ ok: true, id: JOB_ID, phase: 'acquiring', mode: 'preinstall', name: 'new VM' }),
    '/api/preinstall/resume': () => ({ ok: true, job: waitingJob({ phase: 'vpn_resume_queued' }) }),
  };
  const controller = ui.mount({ document, getContext: () => ({ ...context, active: context.active || submitting }), clock: () => now,
    api: async (route, options = {}) => { calls.push({ route, options: JSON.parse(JSON.stringify(options)) }); return handlers[route](options); },
    onBusy: busy => { busyEvents.push(busy); submitting = busy; },
    onQueued: async (job, mode) => { jobs.push(job); queueModes.push(mode); },
    saveExample: (content, filename, mime) => downloads.push({ content, filename, mime }),
  });
  const n = key => document.getElementById('preinstall-' + key);
  async function set(key, value, event = 'input') { if (n(key).type === 'checkbox') n(key).checked = value; else n(key).value = value; await n(key).fire(event); }
  async function manual(open) { n('manual-fields').open = open; await n('manual-fields').fire('toggle'); }
  async function fill() {
    await manual(true);
    for (const [key, value] of Object.entries({ name: 'new VM', protocol: 'tuic', server: '8.8.8.8', port: '443', uuid: UUID, password: 'PRIVATE-password', sni: 'example.com' })) await set(key, value);
  }
  return { document, controller, n, set, manual, fill, calls, handlers, context, downloads, busyEvents, jobs, queueModes,
    wait(job = waitingJob()) { context.active = true; context.waitingJob = job; controller.update(); },
    tick: ms => { now += ms; controller.update(); } };
}
function fields(overrides = {}) { return { protocol: 'tuic', server: '8.8.8.8', port: '443', uuid: UUID, password: 'PRIVATE-password',
  sni: 'example.com', udp: true, security: 'tls', cipher: 'aes-128-gcm', ...overrides }; }

test('new entry/assets are separate from preserved restore-only flow', () => {
  assert.match(html, /id="preinstall-new"[^>]*>新建 VM 及预装软件/);
  assert.match(html, /<details id="create-advanced" class="preinstall-toolbar-more">[\s\S]*?高级选项[\s\S]*?id="new-vm"[^>]*>仅安装 VM[\s\S]*?<\/details>/);
  assert.doesNotMatch(html, /id="offline-validate"|>＋ 新建 VM</);
  assert.ok(html.indexOf('src="/preinstall.js"') < html.indexOf('src="/app.js"'));
  assert.match(html, /href="\/preinstall.css"/);
  assert.match(appSource, /window\.GoldPreinstall\.mount/);
  assert.match(appSource, /openBuild\(null, true\)/);
});

test('the optional download proxy is folded by default and resets on reopen', async () => {
  const f = fixture(); await f.controller.open();
  const settings = f.n('download-settings');
  assert.equal(settings.tagName, 'DETAILS');
  assert.equal(settings.open, false);
  assert.equal(settings.children[0].tagName, 'SUMMARY');
  assert.equal(settings.children[0].textContent, '高级下载设置');
  assert.equal(f.n('downloadProxy').parentNode.parentNode, settings);
  settings.open = true;
  await f.set('downloadProxy', 'http://127.0.0.1:19080');
  assert.equal(settings.children[0].textContent, '高级下载设置（已填写代理）');
  assert.equal(settings.children[0].textContent.includes('127.0.0.1'), false);
  f.n('dialog').close(); await f.controller.open();
  assert.equal(settings.open, false);
  assert.equal(f.n('downloadProxy').value, '');
  assert.equal(settings.children[0].textContent, '高级下载设置');
});

test('all supported form protocols produce precise reviewed schema, not transport guesses', () => {
  const tuic = ui.fieldSubmission(fields({ congestion: 'bbr', relay: 'native', alpn: 'h3' }), false).nodes[0];
  assert.equal(tuic['congestion-controller'], 'bbr'); assert.equal(tuic['disable-sni'], false);
  assert.deepEqual(tuic.alpn, ['h3']); assert.equal('client-fingerprint' in tuic, false);
  const vless = ui.fieldSubmission(fields({ protocol: 'vless', flow: 'xtls-rprx-vision', security: 'reality', realityKey: REALITY_KEY, shortId: '12ab', fingerprint: 'chrome' }), false).nodes[0];
  assert.equal(vless.network, 'tcp'); assert.equal(vless.tls, true); assert.equal(vless.servername, 'example.com');
  assert.deepEqual(vless['reality-opts'], { 'public-key': REALITY_KEY, 'short-id': '12ab' });
  assert.equal('password' in vless, false); assert.equal('sni' in vless, false);
  const trojan = ui.fieldSubmission(fields({ protocol: 'trojan' }), false).nodes[0];
  assert.equal(trojan.network, 'tcp'); assert.equal(trojan.tls, true); assert.equal('uuid' in trojan, false);
  for (const cipher of ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305']) {
    const ss = ui.fieldSubmission(fields({ protocol: 'ss', cipher }), false).nodes[0];
    assert.deepEqual(Object.keys(ss).sort(), ['type', 'server', 'port', 'udp', 'password', 'cipher'].sort());
  }
  const hy = ui.fieldSubmission(fields({ protocol: 'hysteria2', up: '10', down: '100', obfs: 'salamander', obfsPassword: 'PRIVATE-obfs' }), false).nodes[0];
  assert.equal(hy.up, 10); assert.equal(hy.down, 100); assert.equal(hy['obfs-password'], 'PRIVATE-obfs');
  assert.equal('uuid' in hy, false);
});

test('unsupported protocol/cipher, private/IPv6 endpoints, bad ports and insecure input rejected locally', () => {
  for (const overrides of [{ protocol: 'vmess' }, { protocol: 'ss', cipher: 'none' }, { port: '53' }, { port: '443.5' },
    { server: '127.0.0.1' }, { server: '192.168.1.1' }, { server: '203.0.113.1' }, { server: '::1' }, { server: 'https://node.example.com' },
    { uuid: '00000000-0000-0000-0000-000000000000' }, { protocol: 'vless', security: 'ws' }]) {
    assert.throws(() => ui.fieldSubmission(fields(overrides), false));
  }
  assert.throws(() => ui.fieldSubmission(fields({ server: 'vpn.example.com' }), false), /DNS/);
  assert.equal(ui.fieldSubmission(fields({ server: 'vpn.example.com' }), true).nodes[0].server, 'vpn.example.com');
});

test('dynamic protocol controls show only applicable fields without transmitting hidden secrets', async () => {
  const f = fixture(); await f.controller.open();
  await f.set('protocol', 'ss', 'change');
  assert.equal(f.n('uuid').parentNode.hidden, true); assert.equal(f.n('cipher').parentNode.hidden, false);
  assert.equal(f.n('sni').parentNode.hidden, true);
  await f.set('protocol', 'vless', 'change'); await f.set('security', 'reality', 'change');
  assert.equal(f.n('realityKey').parentNode.hidden, false); assert.equal(f.n('password').parentNode.hidden, true);
  await f.set('protocol', 'hysteria2'); await f.set('obfs', 'salamander');
  assert.equal(f.n('obfsPassword').parentNode.hidden, false); assert.equal(f.n('realityKey').parentNode.hidden, true);
});

test('validate sends raw submission only to fixed local endpoint; create sends only opaque id and explicit consents', async () => {
  const f = fixture(); await f.controller.open(); await f.fill(); await f.controller.validate();
  const check = f.calls.find(c => c.route.endsWith('/vpn/validate'));
  assert.equal(check.options.body.allow_resolve, false);
  assert.equal(check.options.body.submission.nodes[0].password, 'PRIVATE-password');
  assert.equal(f.n('submit').disabled, false);
  await f.n('submit').click();
  const create = f.calls.find(c => c.route.endsWith('/create'));
  assert.deepEqual(create.options.body, { name: 'new VM', cpu: 2, memory_gib: 4, disk_gib: 50, ipsw: 'reviewed', vpn_configuration_id: ID,
    download_loopback_proxy: null, acknowledge_preinstall: true, acknowledge_network_policy: true });
  assert.equal(JSON.stringify(create).includes('PRIVATE-password'), false);
  assert.equal(JSON.stringify(create).includes(UUID), false);
  assert.deepEqual(f.busyEvents, [true, false]); assert.equal(f.jobs.length, 1);
  assert.equal(f.n('password').value, ''); assert.equal(f.n('uuid').value, ''); assert.equal(f.n('dialog').open, false);
});

test('configuration changes invalidate the opaque id immediately and stale async responses are discarded', async () => {
  const f = fixture(); await f.controller.open(); await f.fill(); await f.controller.validate();
  await f.set('server', '9.9.9.9'); assert.equal(f.n('submit').disabled, true);
  let finish;
  f.handlers['/api/preinstall/vpn/validate'] = () => new Promise(resolve => { finish = resolve; });
  const pending = f.controller.validate();
  await f.set('password', 'CHANGED-during-request'); finish(validated()); await pending;
  assert.equal(f.n('submit').disabled, true);
  await f.n('submit').click();
  assert.equal(f.calls.filter(c => c.route.endsWith('/create')).length, 0);
});

test('one explicit final button authorizes listed changes, never an implicit form submit', async () => {
  const f = fixture(); f.handlers['/api/preinstall/vpn/validate'] = () => validated(true);
  await f.controller.open(); await f.fill(); await f.controller.validate();
  assert.equal(f.n('ackNormalization'), undefined);
  assert.equal(f.n('ackAutoconfigure'), undefined);
  assert.equal(f.n('normalization-note').hidden, false);
  assert.match(f.n('operation-note').textContent, /不覆盖或自动开机/);
  assert.equal(f.n('submit').type, 'button');
  assert.equal(f.n('submit').disabled, false);
  const implicit = await f.n('dialog').children[0].fire('submit');
  assert.equal(implicit.prevented, true);
  assert.equal(f.calls.filter(c => c.route.endsWith('/create')).length, 0);
  await f.n('submit').click();
  const payload = f.calls.find(c => c.route.endsWith('/create')).options.body;
  assert.equal(payload.acknowledge_normalization, true);
  assert.equal(payload.acknowledge_preinstall, true);
  assert.equal(payload.acknowledge_network_policy, true);
  assert.equal('acknowledge_guest_autoconfigure' in payload, false, 'nothing is configured inside the guest any more');
  assert.equal(f.n('normalization-note').hidden, true);
});

test('only new names, valid explicit local IPSW and credential-free loopback transport accepted', async () => {
  const f = fixture(); await f.controller.open(); await f.fill(); await f.controller.validate();
  await f.set('name', 'EXISTING VM'); assert.equal(f.n('submit').disabled, true);
  await f.set('name', 'new VM'); await f.set('imageMode', 'local');
  await f.set('ipsw', '../untrusted.ipsw'); assert.equal(f.n('submit').disabled, true);
  await f.set('ipsw', '/fixture/reviewed.ipsw'); assert.equal(f.n('submit').disabled, false);
  for (const proxy of ['http://user:password@127.0.0.1:9000', 'http://localhost:9000', 'http://127.0.0.1:9000/path', 'http://127.0.0.1:70000']) {
    await f.set('downloadProxy', proxy); assert.equal(f.n('submit').disabled, true);
  }
  await f.set('downloadProxy', 'http://127.0.0.1:19080'); assert.equal(f.n('submit').disabled, false);
  await f.n('submit').click();
  const payload = f.calls.find(c => c.route.endsWith('/create')).options.body;
  assert.equal(payload.ipsw, '/fixture/reviewed.ipsw'); assert.equal(payload.download_loopback_proxy, 'http://127.0.0.1:19080');
  assert.equal('source_vm' in payload, false); assert.equal('acknowledge_erase' in payload, false);
});

test('local YAML path is the default, has no file input, and is sent only to explicit validation', async () => {
  const f = fixture(); await f.controller.open(); await f.set('name', 'new VM');
  assert.equal(f.n('manual-fields').open, false);
  assert.equal(f.n('manual-fields').children[0].textContent, '手工填写');
  assert.equal(f.n('yaml-panel').hidden, false);
  assert.equal(f.n('yamlPath').type, 'text');
  assert.equal(f.n('yamlPath').parentNode.children[0].textContent, '本地 Clash YAML 绝对路径');
  assert.equal(f.n('upload'), undefined);
  assert.equal(f.controller.uploadFile, undefined);
  assert.doesNotMatch(source, /FileReader|\.files\b|yaml_text|type: 'file'/);
  await f.set('yamlPath', YAML_PATH);
  assert.deepEqual(f.calls, [{ route: '/api/preinstall/capabilities', options: {} }]);
  assert.equal(f.n('capability-blockers').hidden, true);
  assert.equal(f.n('submit').disabled, true);
  await f.n('validate').click();
  const call = f.calls.filter(c => c.route.endsWith('/vpn/validate')).at(-1);
  assert.deepEqual(call.options.body, { submission: { input_mode: 'yaml_path', path: YAML_PATH }, allow_resolve: false });
  assert.equal(f.n('submit').disabled, false);
  await f.manual(true);
  assert.equal(f.n('yaml-panel').hidden, true); assert.equal(f.n('submit').disabled, true);
  await f.manual(false);
  assert.equal(f.n('yaml-panel').hidden, false); assert.equal(f.n('submit').disabled, true);
  await f.n('validate').click(); await f.n('submit').click();
  assert.doesNotMatch(JSON.stringify(f.calls.at(-1)), /Private VPN|yaml_path/);
});

test('noncanonical, nonlocal, or non-YAML paths are rejected without any validation request', async () => {
  const f = fixture(); await f.controller.open();
  for (const value of ['', 'clash.yaml', '~/clash.yaml', 'file:///private/clash.yaml', '//server/clash.yaml',
    '/a//clash.yaml', '/a/../clash.yaml', '/a/./clash.yaml', '/a/clash.yaml\u0000', '/a/clash.yaml ', '/a/config.json']) {
    await f.set('yamlPath', value); await f.n('validate').click();
    assert.equal(f.n('error').hidden, false);
  }
  assert.equal(f.calls.filter(c => c.route.endsWith('/vpn/validate')).length, 0);
  assert.deepEqual(ui.submission({ mode: 'yaml', yamlPath: '/本地配置/Clash.YML' }), { input_mode: 'yaml_path', path: '/本地配置/Clash.YML' });
});

test('fixed public examples download without including current input or any URL query', async () => {
  const f = fixture(); await f.controller.open(); await f.fill();
  await f.controller.downloadExample('yaml'); await f.controller.downloadExample('fields');
  assert.equal(f.downloads.length, 2);
  assert.equal(f.downloads[0].filename, 'preinstall-node-example.yaml');
  assert.equal(f.downloads[1].filename, 'preinstall-node-example.json');
  assert.equal(JSON.stringify(f.downloads).includes('PRIVATE-password'), false);
  assert.ok(f.calls.every(c => !c.route.includes('?')));
  assert.ok(f.calls.filter(c => c.route.endsWith('/examples')).every(c => Object.keys(c.options).length === 0));
});

test('node expiry and disconnected or active lifecycle state disable creation', async () => {
  const f = fixture(); await f.controller.open(); await f.fill(); await f.controller.validate();
  f.context.active = true; f.controller.update(); assert.equal(f.n('submit').disabled, true);
  f.context.active = false; f.context.connected = false; f.controller.update(); assert.equal(f.n('submit').disabled, true);
  f.context.connected = true; f.controller.update(); assert.equal(f.n('submit').disabled, false);
  f.tick(3600 * 1000 + 1); assert.equal(f.n('submit').disabled, true);
});

test('missing complete applications or unavailable capabilities never enable credential submission', async () => {
  const f = fixture(); f.handlers['/api/preinstall/capabilities'] = () => ({ ...capabilities(), applications: capabilities().applications.slice(0, 3) });
  await f.controller.open(); await f.fill(); await f.controller.validate();
  assert.equal(f.calls.filter(c => c.route.endsWith('/vpn/validate')).length, 0);
  assert.equal(f.n('submit').disabled, true);
  assert.match(f.n('dialog').textContent, /4 个应用/);
});

test('validation errors and unknown warnings never render HTML or echo secret details', async () => {
  const f = fixture(); await f.controller.open(); await f.fill();
  f.handlers['/api/preinstall/vpn/validate'] = () => { throw new Error('<img src=x onerror=alert(1)> PRIVATE-password'); };
  await f.controller.validate();
  assert.equal(f.n('error').textContent.includes('PRIVATE-password'), false);
  assert.equal(f.n('error').textContent.includes('<img'), false);
  f.handlers['/api/preinstall/vpn/validate'] = () => { const v = validated(true); v.summary.warnings = ['<script>PRIVATE-password</script>']; return v; };
  await f.controller.validate();
  assert.equal(f.n('dialog').textContent.includes('PRIVATE-password'), false);
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|console\.|localStorage|sessionStorage/);
});

test('a validation response claiming VPN connection is not trusted as successful normalization', () => {
  assert.throws(() => ui.validateResponse({ ...validated(), vpn_connected: true }, 1000));
  assert.throws(() => ui.validateResponse({ ...validated(), configuration_id: 'http://user:secret@host' }, 1000));
});

test('failed create never auto-retries or retains a directly reusable id', async () => {
  const f = fixture(); await f.controller.open(); await f.fill(); await f.controller.validate();
  f.handlers['/api/preinstall/create'] = () => { throw new Error('network response uncertain'); };
  await f.n('submit').click();
  assert.equal(f.n('submit').disabled, true); assert.match(f.n('error').textContent, /先刷新任务状态/);
  await f.n('submit').click();
  assert.equal(f.calls.filter(c => c.route.endsWith('/create')).length, 1);
  assert.deepEqual(f.busyEvents, [true, false]);
});

test('closing dialog clears passwords, the YAML path and the selected input mode', async () => {
  const f = fixture(); await f.controller.open(); await f.set('yamlPath', YAML_PATH);
  await f.fill(); f.n('dialog').close();
  assert.equal(f.n('password').value, ''); assert.equal(f.n('uuid').value, ''); assert.equal(f.n('yamlPath').value, '');
  await f.controller.open(); assert.equal(f.n('manual-fields').open, false);
  await f.controller.validate();
  assert.equal(f.calls.filter(c => c.route.endsWith('/vpn/validate')).length, 0);
});

test('deferring hides and clears VPN input, invalidates old consents, and skips validation entirely', async () => {
  const f = fixture(); f.handlers['/api/preinstall/vpn/validate'] = () => validated(true);
  await f.controller.open();
  assert.equal(f.n('deferVpn').checked, false);
  await f.set('yamlPath', YAML_PATH); await f.fill(); await f.set('allowResolve', true);
  await f.controller.validate(); assert.equal(f.n('normalization-note').hidden, false);
  await f.set('downloadProxy', 'http://127.0.0.1:19080');
  await f.set('deferVpn', true);
  assert.equal(f.n('vpn-inputs').hidden, true);
  assert.equal(f.n('yamlPath').value, ''); assert.equal(f.n('yamlPath').disabled, true);
  assert.equal(f.n('password').value, ''); assert.equal(f.n('uuid').value, '');
  assert.equal(f.n('allowResolve').checked, false);
  assert.equal(f.n('manual-fields').open, false);
  assert.equal(f.n('normalization-note').hidden, true);
  assert.match(f.n('defer-note').textContent, /不会发布或开机，也不会配置客机网络/);
  assert.match(f.n('submit').textContent, /暂不配置 VPN/);
  assert.equal(f.n('submit').disabled, false);
  const cut = f.calls.length;
  await f.n('validate').click(); await f.controller.downloadExample('yaml');
  assert.equal(f.calls.length, cut);
  assert.equal((await f.n('dialog').children[0].fire('submit')).prevented, true);
  assert.equal(f.calls.length, cut);
  await f.n('submit').click();
  assert.deepEqual(f.calls.slice(cut), [{ route: '/api/preinstall/create', options: { method: 'POST', timeout: 30000,
    body: { name: 'new VM', cpu: 2, memory_gib: 4, disk_gib: 50, ipsw: 'reviewed', download_loopback_proxy: 'http://127.0.0.1:19080',
      acknowledge_preinstall: true, defer_vpn: true } } }]);
  assert.deepEqual(f.queueModes, [{ resumed: false, deferred: true }]);
  assert.equal(f.n('deferVpn').checked, false);
});

test('discarded validation cannot reappear after toggling defer off and on', async () => {
  const f = fixture(); await f.controller.open(); await f.set('name', 'new VM'); await f.set('yamlPath', YAML_PATH);
  let finish;
  f.handlers['/api/preinstall/vpn/validate'] = () => new Promise(resolve => { finish = resolve; });
  const pending = f.controller.validate();
  await f.set('deferVpn', true); await f.set('deferVpn', false);
  finish(validated(true)); await pending;
  assert.equal(f.n('yamlPath').value, '');
  assert.equal(f.n('normalization-note').hidden, true);
  assert.equal(f.n('submit').disabled, true);
  assert.doesNotMatch(f.n('summary').textContent, /已私有保存/);
  await f.n('submit').click();
  assert.equal(f.calls.filter(c => c.route.endsWith('/create')).length, 0);
});

test('a waiting job still allows the background preflight and an explicit path validation then single resume consent', async () => {
  for (const normalization of [false, true]) {
    const f = fixture(); f.wait();
    f.handlers['/api/preinstall/vpn/validate'] = () => validated(normalization);
    await f.controller.open();
    await f.controller.openResume('c'.repeat(32));
    assert.deepEqual(f.calls, []); assert.equal(f.n('dialog').open, false);
    await f.controller.openResume(JOB_ID);
    assert.deepEqual(f.calls, [{ route: '/api/preinstall/capabilities', options: {} }]);
    assert.equal(f.n('capability-blockers').hidden, true);
    assert.match(f.n('title').textContent, /继续配置 VPN · new VM/);
    assert.equal(f.n('name').parentNode.parentNode.hidden, true);
    assert.equal(f.n('deferVpn').parentNode.hidden, true);
    assert.equal(f.n('manual-fields').open, false);
    assert.equal(f.n('yaml-panel').hidden, false);
    assert.equal(f.n('validate').disabled, false);
    assert.equal(f.n('submit').disabled, true);
    await f.set('yamlPath', YAML_PATH);
    assert.equal(f.calls.length, 1);
    await f.n('validate').click();
    assert.deepEqual(f.calls[1].options.body, { submission: { input_mode: 'yaml_path', path: YAML_PATH }, allow_resolve: false });
    assert.equal(f.n('normalization-note').hidden, !normalization);
    assert.equal(f.n('submit').textContent, '同意并继续配置 VPN');
    assert.equal(f.n('submit').disabled, false);
    assert.equal((await f.n('dialog').children[0].fire('submit')).prevented, true);
    assert.equal(f.calls.length, 2);
    await f.n('submit').click();
    assert.deepEqual(f.calls[2], { route: '/api/preinstall/resume', options: { method: 'POST', timeout: 30000,
      body: { job_id: JOB_ID, vpn_configuration_id: ID, acknowledge_network_policy: true,
        ...(normalization ? { acknowledge_normalization: true } : {}) } } });
    assert.deepEqual(f.queueModes, [{ resumed: true, deferred: false }]);
    assert.deepEqual(f.jobs, [waitingJob({ phase: 'vpn_resume_queued' })]);
    assert.equal(f.n('dialog').open, false); assert.equal(f.n('yamlPath').value, '');
    assert.ok(f.calls.every(c => !c.route.includes('?')));
  }
});

test('resume rejects stale scope even with the same returned job ID, and clears stale validation and path', async () => {
  const f = fixture(); f.wait(); await f.controller.openResume(JOB_ID);
  f.handlers['/api/preinstall/vpn/validate'] = () => validated(true);
  await f.set('yamlPath', YAML_PATH); await f.n('validate').click();
  assert.equal(f.n('normalization-note').hidden, false);
  await f.set('yamlPath', '/private/changed.yml');
  assert.equal(f.n('normalization-note').hidden, true);
  let finish;
  f.handlers['/api/preinstall/vpn/validate'] = () => new Promise(resolve => { finish = resolve; });
  const pending = f.controller.validate();
  f.wait(waitingJob({ phase: 'resuming_vpn' }));
  f.wait(); // Observing the stale phase permanently invalidates this dialog scope.
  finish(validated(true)); await pending;
  assert.equal(f.n('yamlPath').value, '');
  assert.equal(f.n('validate').disabled, true);
  assert.equal(f.n('submit').disabled, true);
  assert.equal(f.n('normalization-note').hidden, true);
  assert.match(f.n('error').textContent, /待配置任务已变化/);
  await f.n('submit').click();
  assert.equal(f.calls.filter(c => c.route.endsWith('/resume')).length, 0);
  f.n('dialog').close(); await f.controller.openResume(JOB_ID);
  assert.equal(f.n('validate').disabled, false);
  assert.equal(f.n('submit').disabled, true);
});

test('resume does not accept an unexpected queued identity and never automatically reposts', async () => {
  const f = fixture(); f.wait(); await f.controller.openResume(JOB_ID);
  await f.set('yamlPath', YAML_PATH); await f.n('validate').click();
  f.handlers['/api/preinstall/resume'] = () => ({ ok: true, job: waitingJob({ id: 'c'.repeat(32), phase: 'vpn_resume_queued' }) });
  await f.n('submit').click(); await f.n('submit').click();
  assert.equal(f.n('dialog').open, true);
  assert.equal(f.n('submit').disabled, true);
  assert.match(f.n('error').textContent, /先刷新任务状态/);
  assert.equal(f.calls.filter(c => c.route.endsWith('/resume')).length, 1);
  assert.equal(f.jobs.length, 0);
});

function declaration(name) {
  const start = appSource.search(new RegExp('^  (?:async )?function ' + name + '\\(', 'm'));
  assert.ok(start >= 0, name);
  const end = appSource.indexOf('\n  }', start) + 4;
  return appSource.slice(start, end);
}

test('shared folders keep management actions but offer no host Claude command', () => {
  const choices = declaration('renderShares');
  for (const label of ['在 Finder 中显示', '编辑', '启用', '停用', '移除']) assert.ok(choices.includes(label));
  assert.match(choices, /客机目录：\/Volumes\/My Shared Files/);
  assert.doesNotMatch(appSource, /copyCommand|shellQuote|复制 Claude 命令|&& claude|主机 Claude Code/);
});

test('all active preinstall phases and existing offline recovery lock VM actions and builds', () => {
  const sandbox = { state: {}, preinstallBusy: false };
  vm.createContext(sandbox); vm.runInContext(declaration('buildActive'), sandbox);
  for (const phase of ['acquiring', 'installing', 'awaiting_vpn_configuration', 'vpn_resume_queued', 'resuming_vpn', 'preparing_runtime', 'publishing']) {
    sandbox.state.build_job = { mode: 'preinstall', phase }; assert.equal(sandbox.buildActive(), true, phase);
  }
  sandbox.state.build_job = { phase: 'failed', recovery_required: true }; assert.equal(sandbox.buildActive(), true);
  sandbox.state.build_job = { phase: 'awaiting_offline_preinstall', offline_preinstall: { active: true } }; assert.equal(sandbox.buildActive(), true);
  sandbox.state.build_job = null; sandbox.preinstallBusy = true; assert.equal(sandbox.buildActive(), true);
  assert.match(appSource, /function locked\(vm\) \{ return !connected \|\| vmBusy\(vm\) \|\| buildActive\(\); \}/);
});

test('waiting build status offers only the matching continuation and disables it while disconnected or submitting', async () => {
  const region = { children: [], hidden: false, classList: { toggle() {} }, replaceChildren() { this.children = []; }, append(...v) { this.children.push(...v); } };
  const opened = [];
  const sandbox = { state: { build_job: waitingJob() }, selectedVM: 'other', $: () => region, el: (tag, cls, text) => ({ tag, text }),
    connected: true, preinstallBusy: false, preinstallUI: { openResume: async id => opened.push(id) }, window: { GoldPreinstall: ui },
    button: (text, cls, click, disabled) => ({ text, click, disabled }) };
  vm.createContext(sandbox);
  for (const name of ['waitingVpnJob', 'openWaitingVpnConfiguration', 'renderBuildJob']) vm.runInContext(declaration(name), sandbox);
  sandbox.renderBuildJob();
  assert.equal(region.hidden, false);
  assert.match(region.children.map(n => n.text).join(' '), /系统已恢复.*尚未配置客机网络.*尚未发布或启动/);
  const continuation = region.children.filter(n => n.click);
  assert.deepEqual(continuation.map(n => n.text), ['继续配置 VPN']); assert.deepEqual(opened, []);
  await continuation[0].click(); assert.deepEqual(opened, [JOB_ID]);
  sandbox.state.build_job = waitingJob({ id: 'c'.repeat(32) });
  await continuation[0].click(); assert.deepEqual(opened, [JOB_ID]);
  sandbox.state.build_job = waitingJob({ name: 'different VM' });
  await continuation[0].click(); assert.deepEqual(opened, [JOB_ID]);
  sandbox.state.build_job = waitingJob();
  sandbox.connected = false; sandbox.renderBuildJob(); assert.equal(region.children.at(-1).disabled, true);
  await region.children.at(-1).click(); assert.deepEqual(opened, [JOB_ID]);
  sandbox.connected = true; sandbox.preinstallBusy = true; sandbox.renderBuildJob(); assert.equal(region.children.at(-1).disabled, true);
  await region.children.at(-1).click(); assert.deepEqual(opened, [JOB_ID]);
  sandbox.preinstallBusy = false;
  for (const phase of ['vpn_resume_queued', 'resuming_vpn']) {
    sandbox.state.build_job = waitingJob({ phase });
    sandbox.renderBuildJob(); assert.equal(region.children.some(n => n.click), false);
  }
});

test('failed material preparation never mentions administrator access', () => {
  const region = { children: [], classList: { toggle() {} }, replaceChildren() { this.children = []; }, append(...v) { this.children.push(...v); } };
  const sandbox = { state: { build_job: { mode: 'preinstall', name: 'gg1', phase: 'failed',
    failed_phase: 'acquiring', failure_code: 'unsafe-tar-path', system_restored: false, message: '旧授权提示' } },
    selectedVM: '', $: () => region, el: (tag, cls, text) => ({ tag, text }),
    button: () => { throw new Error('Must not offer a startup action'); } };
  vm.createContext(sandbox); vm.runInContext(declaration('renderBuildJob'), sandbox);
  sandbox.renderBuildJob();
  const text = region.children.map(n => n.text).join(' ');
  assert.match(text, /材料准备失败.*Tart.*尚未创建虚拟磁盘/);
  assert.doesNotMatch(text, /管理员授权|亲自完成|旧授权提示/);
});

test('published/static-written job phases never claim connected VPN or automatically start a VM', () => {
  const region = { children: [], hidden: false, classList: { toggle() {} }, replaceChildren() { this.children = []; }, append(...v) { this.children.push(...v); } };
  const sandbox = { state: {}, selectedVM: 'other', $: () => region, el: (tag, cls, text) => ({ tag, text }),
    button: () => { throw new Error('No automatic startup action'); } };
  vm.createContext(sandbox); vm.runInContext(declaration('renderBuildJob'), sandbox);
  for (const phase of ['acquiring', 'preparing_runtime', 'publishing', 'awaiting_first_desktop_acceptance', 'failed']) {
    sandbox.state.build_job = { mode: 'preinstall', phase, name: 'new VM', vpn: { config_written: true }, progress: null };
    sandbox.renderBuildJob();
    const text = region.children.map(n => n.text).join(' ');
    assert.match(text, /一键预装/); assert.match(text, /不代表 VPN 已连通/); assert.match(text, /亲自完成/);
  }
  assert.doesNotMatch(source, /\/api\/vms\/.*\/action|action:\s*['"]start|source_vm|acknowledge_erase/);
});

function jobRegion() {
  return { children: [], hidden: false, classList: { toggle() {} }, replaceChildren() { this.children = []; }, append(...v) { this.children.push(...v); } };
}

function renderFailedJob(job, extra = {}) {
  const region = jobRegion();
  const buttons = [];
  const sandbox = Object.assign({ state: { build_job: job }, selectedVM: '', connected: true, $: () => region,
    el: (tag, cls, text) => ({ tag, cls, text }),
    button: (text, cls, click, disabled) => { const item = { text, click, disabled }; buttons.push(item); return item; } }, extra);
  vm.createContext(sandbox);
  vm.runInContext(declaration('renderBuildJob'), sandbox);
  sandbox.renderBuildJob();
  return { text: region.children.map(n => n.text).filter(Boolean).join('\n'), buttons: buttons.map(b => ({ text: b.text, disabled: b.disabled })) };
}

test('failed preinstall card names the failed step, explains the reason and keeps the raw codes', () => {
  const { text, buttons } = renderFailedJob({ id: JOB_ID, mode: 'preinstall', name: 'backup1', phase: 'failed',
    failed_phase: 'preparing_runtime', failure_code: 'installer-copy-mismatch', recovery_required: true, published: false,
    message: '预装未完成；保留所有暂存文件，不自动覆盖重试。请查看失败步骤。' });
  assert.match(text, /失败步骤：准备首次设置文件夹与受保护启动（preparing_runtime）/);
  assert.match(text, /原因：复制后的应用与已核验的原件不一致/);
  assert.match(text, /代码：installer-copy-mismatch/);
  assert.match(text, /不代表 VPN 已连通/);
  assert.doesNotMatch(text, /管理员授权|属主/);
  assert.equal(JSON.stringify(buttons), JSON.stringify([{ text: '归档此失败任务（保留暂存盘）', disabled: false }]));
});

test('failure details fall back to phase labels and never invent a reason', () => {
  let view = renderFailedJob({ id: JOB_ID, mode: 'preinstall', name: 'n1', phase: 'failed', failed_phase: 'installing',
    failure_code: 'apple-restore-not-complete', recovery_required: true });
  assert.match(view.text, /失败步骤：离线安装系统（installing）/);
  assert.match(view.text, /代码：apple-restore-not-complete/);
  view = renderFailedJob({ id: JOB_ID, mode: 'preinstall', name: 'n3', phase: 'failed', failed_phase: 'mystery_phase',
    failure_code: 'unheard-of-code', recovery_required: false });
  assert.match(view.text, /失败步骤：mystery_phase/);
  assert.match(view.text, /代码：unheard-of-code/);
  assert.match(view.text, /原因：未归类/);
  assert.equal(view.buttons.length, 0, 'no archive action when nothing is locked');
  view = renderFailedJob({ id: JOB_ID, mode: 'preinstall', name: 'n4', phase: 'failed', failed_phase: 'publishing',
    failure_code: 'publication-registry-readback-failed', recovery_required: true, published: true });
  assert.equal(view.buttons.filter(b => b.text.startsWith('归档')).length, 0, 'a published job is never archived from the UI');
  view = renderFailedJob({ id: JOB_ID, mode: 'preinstall', name: 'n5', phase: 'failed', failed_phase: 'installing',
    failure_code: 'apple-restore-not-complete', recovery_required: true }, { connected: false });
  assert.equal(view.buttons[0].disabled, true);
  assert.doesNotMatch(appSource.slice(appSource.indexOf('function renderBuildJob'), appSource.indexOf('function openBuild')), /innerHTML/);
});

test('archiving a failed job is one click and sends only the job id and name', async () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, { id, value: '', hidden: false, disabled: false, textContent: '', className: '', required: false,
      open: false, showModal() { this.open = true; }, close() { this.open = false; }, focus() {}, querySelectorAll() { return []; } });
    return nodes.get(id);
  };
  const calls = [];
  const sandbox = { $: node, connected: true, confirmContext: null, confirmBusy: false, buildActive: () => true,
    api: async (route, options) => { calls.push([route, options.method, options.body]); return { ok: true, stage_retained: true }; },
    refresh: async () => { calls.push(['refresh']); }, toast: () => {}, showError: (id, message) => { throw new Error(message); } };
  vm.createContext(sandbox);
  for (const name of ['openArchiveJob', 'submitConfirm']) vm.runInContext(declaration(name), sandbox);
  const job = { id: JOB_ID, mode: 'preinstall', name: 'backup1', phase: 'failed', recovery_required: true, published: false };
  sandbox.openArchiveJob(Object.assign({}, job, { recovery_required: false }));
  assert.equal(node('confirm-dialog').open, false, 'only locked failed jobs can be archived');
  sandbox.openArchiveJob(job);
  assert.equal(node('confirm-dialog').open, true);
  assert.match(node('confirm-description').textContent, /\.gold-manager-staging/);
  assert.match(node('confirm-description').textContent, /不会删除/);
  assert.equal(node('confirm-submit').disabled, false, 'no typed name: the button itself confirms');
  await sandbox.submitConfirm({ preventDefault() {} });
  assert.equal(JSON.stringify(calls[0]), JSON.stringify(['/api/preinstall/archive', 'POST', { job_id: JOB_ID, confirm_name: 'backup1' }]));
  assert.equal(node('confirm-dialog').open, false);
});

test('no dialog asks to type a VM name, and the retired administrator pause is gone', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'static', 'index.html'), 'utf8');
  for (const id of ['confirm-name', 'confirm-input-group', 'delete-name', 'delete-erase-ack', 'build-confirm']) {
    assert.doesNotMatch(html, new RegExp(`id="${id}"`), id);
    assert.doesNotMatch(appSource, new RegExp(`'${id}'`), id);
  }
  assert.doesNotMatch(appSource, /\/api\/preinstall\/authorization|pausedAuthorization|authorization_retry/);
  assert.match(appSource, /body: \{ confirm_name: id, acknowledge_erase: true \}/);
});

test('a material failure names the product, explains the transfer cause and keeps the code', () => {
  const failed = (changes = {}) => renderFailedJob(Object.assign({ id: JOB_ID, mode: 'preinstall', name: 'bb1', phase: 'failed',
    failed_phase: 'acquiring', system_restored: false, failure_code: 'download-timeout', failed_product: 'ccbaga' }, changes));
  let view = failed();
  assert.match(view.text, /材料准备失败/);
  assert.match(view.text, /失败项目：CCBaga/);
  assert.match(view.text, /原因：30 秒内没有收到/);
  assert.match(view.text, /代码：download-timeout/);
  assert.doesNotMatch(view.text, /管理员授权|亲自完成/);
  view = failed({ failure_code: 'download-connection-lost', failed_product: 'clashVergeRev' });
  assert.match(view.text, /失败项目：Clash Verge/);
  assert.match(view.text, /连接被中断/);
  view = failed({ failure_code: 'downloading-failed', failed_product: '../x' });
  assert.doesNotMatch(view.text, /失败项目/, 'an unknown product is never shown');
  assert.match(view.text, /原因：未能识别具体原因/);
  assert.match(view.text, /代码：downloading-failed/);
  view = failed({ failure_code: 'host-disk-full', failed_product: undefined });
  assert.match(view.text, /磁盘空间不足/);
});

test('the job card says whether application materials were reused or downloaded', () => {
  const job = (source) => ({ id: JOB_ID, mode: 'preinstall', name: 'bb2', phase: 'acquiring', materials_source: source });
  assert.match(renderFailedJob(job('reused')).text, /应用材料：复用本机已校验的缓存（本次已重新完整校验）/);
  assert.match(renderFailedJob(job('downloaded')).text, /应用材料：本次重新下载/);
  assert.doesNotMatch(renderFailedJob(job('elsewhere')).text, /应用材料/);
});

test('first setup starts on the normal network with its own one-click consent; marking it finished switches to protected starts', async () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, { id, value: '', hidden: false, disabled: false, textContent: '', className: '', required: false,
      open: false, showModal() { this.open = true; }, close() { this.open = false; }, focus() {}, querySelectorAll() { return []; } });
    return nodes.get(id);
  };
  const calls = [];
  let current = { id: 'gold', state: 'stopped', preinstalled: { first_setup_pending: true, installers_share: true } };
  const sandbox = { $: node, connected: true, confirmContext: null, confirmBusy: false, lastActionError: '', busyVMs: new Set(),
    buildActive: () => false, locked: () => false, vmById: () => current, render: () => {},
    api: async (route, options) => { calls.push(JSON.stringify([route, options.method, options.body])); return { ok: true, message: 'ok' }; },
    refresh: async () => {}, toast: () => {}, showError: (id, message) => { throw new Error(message); } };
  vm.createContext(sandbox);
  vm.runInContext(appSource.match(/^ {2}const ACTION_LABELS = .*;$/m)[0].replace('const ', 'var '), sandbox);
  for (const name of ['openActionConfirm', 'submitConfirm', 'runAction']) vm.runInContext(declaration(name), sandbox);
  const submit = () => sandbox.submitConfirm({ preventDefault() {} });

  sandbox.openActionConfirm('gold', 'start');
  assert.equal(node('confirm-dialog').open, true);
  assert.match(node('confirm-description').textContent, /普通网络/);
  assert.match(node('confirm-description').textContent, /真实 IP/);
  assert.match(node('confirm-description').textContent, /标记首次设置完成/);
  assert.match(node('confirm-description').textContent, /gold-installers/);
  assert.match(node('confirm-description').textContent, /用 Finder 把应用拖进「应用程序」/);
  assert.doesNotMatch(node('confirm-description').textContent, /输入/);
  assert.equal(node('confirm-submit').textContent, '用普通网络启动首次设置');
  assert.equal(node('confirm-submit').disabled, false, 'one click confirms; no typed name');
  await submit();
  assert.equal(calls.pop(), JSON.stringify(['/api/vms/gold/action', 'POST', { action: 'start', confirm_name: 'gold', first_setup_normal_network: true }]));
  assert.equal(node('confirm-dialog').open, false);

  // A stale or forged call can never mix the two consents or target another VM.
  for (const args of [['gold', true, false], ['gold', true, true], ['gold ', false, true], [undefined, false, true]]) {
    assert.equal(await sandbox.runAction('gold', 'start', args[0], args[1], args[2]), false, JSON.stringify(args));
  }
  assert.equal(calls.length, 0);

  sandbox.openActionConfirm('gold', 'finish-first-setup');
  assert.match(node('confirm-description').textContent, /不能撤销/);
  assert.match(node('confirm-description').textContent, /连上节点/);
  await submit();
  assert.equal(calls.pop(), JSON.stringify(['/api/vms/gold/action', 'POST', { action: 'finish-first-setup' }]));

  current = { id: 'gold', state: 'stopped', preinstalled: { first_setup_pending: false, installers_share: true } };
  sandbox.openActionConfirm('gold', 'finish-first-setup');
  assert.equal(node('confirm-dialog').open, false, 'nothing to mark once first setup is finished');
  sandbox.openActionConfirm('gold', 'start');
  assert.equal(node('confirm-submit').textContent, '同意尝试受保护启动');
  assert.doesNotMatch(node('confirm-description').textContent, /普通网络启动首次设置|输入/);
  await submit();
  assert.equal(calls.pop(), JSON.stringify(['/api/vms/gold/action', 'POST', { action: 'start', confirm_name: 'gold', acknowledge_reviewed_unsigned_backend: true }]));
  assert.equal(await sandbox.runAction('gold', 'start', 'gold', false, true), false, 'no normal network once first setup is finished');
  assert.equal(calls.length, 0);

  const card = declaration('renderMachine');
  assert.match(card, /标记首次设置完成…/);
  assert.match(card, /首次设置 · 普通网络，未过滤/);
  assert.match(card, /network\.normal_network/);
  assert.match(card, /gold-installers/);
});

test('an older preinstalled VM keeps its own first-setup wording without the installers folder', () => {
  const nodes = new Map();
  const node = (id) => {
    if (!nodes.has(id)) nodes.set(id, { id, value: '', hidden: false, disabled: false, textContent: '', className: '', required: false,
      open: false, showModal() { this.open = true; }, close() { this.open = false; }, focus() {}, querySelectorAll() { return []; } });
    return nodes.get(id);
  };
  const sandbox = { $: node, connected: true, confirmContext: null, locked: () => false, buildActive: () => false,
    vmById: () => ({ id: 'bb1', state: 'stopped', preinstalled: { first_setup_pending: true, installers_share: false } }) };
  vm.createContext(sandbox);
  vm.runInContext(appSource.match(/^ {2}const ACTION_LABELS = .*;$/m)[0].replace('const ', 'var '), sandbox);
  vm.runInContext(declaration('openActionConfirm'), sandbox);
  sandbox.openActionConfirm('bb1', 'start');
  assert.match(node('confirm-description').textContent, /自动导入节点/);
  assert.doesNotMatch(node('confirm-description').textContent, /gold-installers/);
});
