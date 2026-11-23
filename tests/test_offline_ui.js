// Fixture-only UI contract tests: no browser, HTTP, VM, credentials or processes.
// Run: node --test tests/test_offline_ui.js
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'static/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'static/index.html'), 'utf8');
function declaration(name) {
  const start = source.search(new RegExp('^  (?:async )?function ' + name + '\\(', 'm'));
  assert.ok(start >= 0, name);
  const end = source.indexOf('\n  }', start) + 4;
  return source.slice(start, end);
}
function fixture() {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, { value: '', checked: false, hidden: false, disabled: false,
      textContent: '', children: [], classList: { toggle() {} }, checkValidity: () => true,
      setAttribute(name, value) { this[name] = value; },
      focus() {}, showModal() { this.open = true; }, close() { this.open = false; },
      querySelectorAll() { return []; }, reset() {
        for (const n of nodes.values()) { n.value = ''; n.checked = false; }
        node('build-image-mode').value = 'latest';
      }, replaceChildren(...items) { this.children = items; }, append(...items) { this.children.push(...items); },
    });
    return nodes.get(id);
  }
  // Model native number-input validity from the real form, not a fixture policy.
  const disk = node('build-disk'), tag = html.match(/<input id="build-disk"[^>]*>/)[0];
  const [min, max, step] = ['min', 'max', 'step'].map(key => Number(tag.match(new RegExp(` ${key}="(\\d+)"`))[1]));
  disk.checkValidity = () => disk.value !== '' && Number(disk.value) >= min && Number(disk.value) <= max && (Number(disk.value) - min) % step === 0;
  const bodies = [];
  const sandbox = {
    $: node, connected: true, buildBusy: false, buildContext: null, selectedVM: 'other',
    state: { host: { cpu_count: 10, memory_gib: 64 }, capabilities: { offline_validate: true } },
    buildActive: () => false, setSetupProfile: () => {}, vmById: () => ({ state: 'stopped' }),
    readSetupProfile: () => ({ version: 1 }), showError: (id, message) => { throw new Error(message); },
    api: async (route, { body }) => { assert.equal(route, '/api/build'); bodies.push(body); return { message: 'queued' }; },
    refresh: async () => {}, toast: () => {}, selectVM: () => { throw new Error('Unpublished VM must not be selectable'); },
    el: (tag, cls, text) => ({ tag, text }), button: () => { throw new Error('Unpublished VM must not have action button'); },
  };
  vm.createContext(sandbox);
  for (const name of ['openBuild', 'updateBuildForm', 'submitBuild', 'renderBuildJob']) vm.runInContext(declaration(name), sandbox);
  function fill() {
    node('build-name').value = 'gg1'; node('build-ipsw').value = '/fixture/approved.ipsw';
    node('build-offline-ack').checked = true;
    sandbox.updateBuildForm();
  }
  return { node, bodies, sandbox, fill };
}

test('offline entry requires server capability and is separate from legacy consent', () => {
  for (const id of ['create-advanced', 'new-vm', 'build-offline-notice', 'build-offline-ack', 'build-legacy-setup']) {
    assert.ok(html.includes(`id="${id}"`));
  }
  const f = fixture();
  f.sandbox.state.capabilities.offline_validate = false;
  f.sandbox.openBuild(null, true);
  assert.equal(f.sandbox.buildContext, null);
  f.sandbox.state.capabilities.offline_validate = true;
  f.sandbox.openBuild(null, true);
  assert.equal(f.node('build-image-mode').value, 'local');
  assert.equal(f.node('build-image-mode').disabled, true);
  assert.equal(f.node('build-legacy-setup').hidden, true);
  assert.equal(f.node('build-offline-notice').hidden, false);
  assert.equal(f.node('build-submit').disabled, true);
  f.node('build-setup-ack').checked = true;
  f.sandbox.updateBuildForm();
  assert.equal(f.node('build-submit').disabled, true);
});

test('offline request contains no setup/node migration, erase or source fields', async () => {
  const f = fixture();
  f.sandbox.readSetupProfile = () => { throw new Error('Offline must not read setup profile'); };
  f.sandbox.openBuild(null, true); f.fill();
  assert.equal(f.node('build-submit').disabled, false);
  await f.sandbox.submitBuild({ preventDefault() {} });
  assert.equal(f.bodies.length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(f.bodies[0])), {
    mode: 'offline_validate', name: 'gg1', cpu: 2, memory_gib: 4, disk_gib: 50,
    ipsw: '/fixture/approved.ipsw', acknowledge_offline: true,
  });
  assert.equal(f.node('build-image-mode').disabled, true);
});

test('legacy creation is no longer opened by the UI; explicit rebuild keeps its consent gates', async () => {
  const f = fixture();
  f.sandbox.openBuild();
  assert.equal(f.sandbox.buildContext, null);
  f.sandbox.openBuild(null, true); f.fill();
  f.sandbox.openBuild('old-fixture');
  assert.equal(f.node('build-legacy-setup').hidden, false);
  assert.equal(f.node('build-offline-notice').hidden, true);
  assert.equal(f.node('build-image-mode').disabled, false);
  f.node('build-name').value = 'new-fixture'; f.node('build-setup-ack').checked = true;
  f.sandbox.updateBuildForm();
  assert.equal(f.node('build-submit').disabled, true);
  f.node('build-erase-ack').checked = true;
  await f.sandbox.submitBuild({ preventDefault() {} });
  assert.equal(f.bodies[0].mode, 'rebuild');
  assert.equal(f.bodies[0].source_vm, 'old-fixture');
  assert.equal(f.bodies[0].acknowledge_setup, true);
  assert.equal('acknowledge_offline' in f.bodies[0], false);
});

test('offline installation and legacy rebuild explain invalid disk sizes and send the chosen integer', async () => {
  assert.match(html, /<label for="build-disk">[^<]*30–1024 GiB[^<]*整数/);
  assert.match(html, /id="build-disk-note"[^>]*>[^<]*较小[^<]*macOS[^<]*更新/);
  assert.match(html, /id="build-disk-error"[^>]*>磁盘容量无效：[^<]*30–1024 GiB[^<]*整数/);
  for (const offline of [true, false]) {
    const f = fixture();
    for (const [disk, ok] of [[29, false], [30, true], [31, true], [49, true], [50, true], [1024, true], [1025, false], [30.5, false], ['', false]]) {
      if (!f.node('build-dialog').open) {
        f.sandbox.openBuild(offline ? null : 'old-fixture', offline);
        assert.equal(f.node('build-disk').value, '50');
        f.node('build-name').value = 'new-fixture';
        if (offline) { f.node('build-ipsw').value = '/fixture/approved.ipsw'; f.node('build-offline-ack').checked = true; }
        else { f.node('build-setup-ack').checked = true; f.node('build-erase-ack').checked = true; }
      }
      f.node('build-disk').value = String(disk); f.sandbox.updateBuildForm();
      assert.equal(f.node('build-submit').disabled, !ok, `disk ${disk}`);
      assert.equal(f.node('build-disk-error').hidden, ok);
      if (ok) {
        await f.sandbox.submitBuild({ preventDefault() {} });
        assert.equal(f.bodies.at(-1).disk_gib, disk);
      }
    }
    assert.deepEqual(f.bodies.map(body => body.disk_gib), [30, 31, 49, 50, 1024]);
  }
});

test('restored-only job is never labelled preinstalled or linked to VM startup', () => {
  const f = fixture();
  f.sandbox.state.build_job = { name: 'gg1', mode: 'offline_validate', phase: 'awaiting_offline_preinstall',
    progress: null, message: '应用未预装，首次桌面未验收' };
  f.sandbox.renderBuildJob();
  assert.equal(f.node('build-job').hidden, false);
  assert.match(f.node('build-job').children[0].text, /仅安装 VM gg1.*应用未预装.*未启动/);
});

test('verified offline apps are still unpublished and have no startup action', () => {
  const f = fixture();
  f.sandbox.state.build_job = { name: 'gg1', mode: 'offline_validate', phase: 'awaiting_first_desktop_acceptance',
    progress: null, applications_preinstalled: true, guest_started: false, desktop_verified: false,
    message: '完整应用经只读重挂验收；未发布、未启动，不是产品交付' };
  f.sandbox.renderBuildJob();
  assert.match(f.node('build-job').children[0].text, /gg1 · 未启动 · 待首次设置/);
});

test('in-flight offline copy and recovery state block new build controls', () => {
  const f = fixture();
  vm.runInContext(declaration('buildActive'), f.sandbox);
  f.sandbox.state.build_job = { phase: 'awaiting_offline_preinstall', offline_preinstall: { active: true } };
  assert.equal(f.sandbox.buildActive(), true);
  f.sandbox.openBuild(null, true);
  assert.equal(f.sandbox.buildContext, null);
  f.sandbox.state.build_job = { phase: 'failed', recovery_required: true, offline_preinstall: { active: false } };
  assert.equal(f.sandbox.buildActive(), true);
  f.sandbox.state.build_job = { phase: 'awaiting_first_desktop_acceptance', offline_preinstall: { active: false } };
  assert.equal(f.sandbox.buildActive(), false);
});
