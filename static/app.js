(() => {
  'use strict';

  let VM_IDS = [];
  let buildContext = null;
  let buildBusy = false;
  let preinstallBusy = false;
  let preinstallUI = null;
  const TOKEN_KEY = 'gold-vm-manager-token';
  const STATE_LABELS = { running: '运行中', stopped: '已关机', suspended: '已暂停', missing: '未找到' };
  const ACTION_LABELS = { start: '启动', 'recovery-start': '恢复模式启动', pause: '暂停', shutdown: '正常关机', 'force-stop': '强制停止', 'discard-state': '丢弃暂停状态', focus: '打开窗口', 'finish-first-setup': '标记首次设置完成' };
  const $ = (id) => document.getElementById(id);
  let token = '';
  let state = null;
  let selectedVM = 'gold';
  let connected = false;
  let lastError = '';
  let pollFlight = null;
  let renderedSignature = '';
  let shareContext = null;
  let confirmContext = null;
  let dialogBusy = false;
  let confirmBusy = false;
  let lastActionError = '';
  let nativePickerBusy = false;
  let deleteContext = null;
  let deleteBusy = false;
  let growthContext = null;
  const GIB = 2 ** 30;
  let initializeContext = null;
  const SETUP_LANGUAGES = [['en-US', 'English (United States)'], ['en-GB', 'English (United Kingdom)'], ['zh-Hans', '简体中文'], ['zh-Hant', '繁體中文'], ['ja', '日本語'], ['de', 'Deutsch'], ['fr', 'Français']];
  const SETUP_COUNTRIES = [['US', 'United States'], ['GB', 'United Kingdom'], ['JP', 'Japan'], ['SG', 'Singapore'], ['DE', 'Germany'], ['CA', 'Canada'], ['AU', 'Australia'], ['FR', 'France'], ['NL', 'Netherlands'], ['HK', 'Hong Kong']];
  const SETUP_TIMEZONES = [['America/Los_Angeles', 'Los Angeles'], ['America/New_York', 'New York'], ['America/Chicago', 'Chicago'], ['America/Toronto', 'Toronto'], ['America/Vancouver', 'Vancouver'], ['Europe/London', 'London'], ['Europe/Berlin', 'Berlin'], ['Europe/Paris', 'Paris'], ['Europe/Amsterdam', 'Amsterdam'], ['Asia/Tokyo', 'Tokyo'], ['Asia/Singapore', 'Singapore'], ['Asia/Hong_Kong', 'Hong Kong'], ['Australia/Sydney', 'Sydney'], ['Australia/Perth', 'Perth'], ['Etc/UTC', 'UTC']];
  const busyVMs = new Set();

  // Tokens never enter the DOM, URLs after initialization, logs, or error text.
  try { token = sessionStorage.getItem(TOKEN_KEY) || ''; } catch (_) { /* In-memory session still works. */ }
  const fragment = new URLSearchParams(location.hash.slice(1));
  if (fragment.has('token')) {
    token = fragment.get('token') || '';
    try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { /* Private browser settings. */ }
    history.replaceState(null, '', location.pathname + location.search);
  }

  function el(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text !== undefined && text !== null) item.textContent = String(text);
    return item;
  }

  function button(label, className, handler, disabled = false, key) {
    const item = el('button', className, label);
    item.type = 'button';
    item.disabled = disabled;
    if (key) item.dataset.focusKey = key;
    item.addEventListener('click', handler);
    return item;
  }

  function actionButton(label, icon, className, handler, disabled, key) {
    const item = button('', className, handler, disabled, key);
    const paths = {
      play: 'M8 5l11 7-11 7V5Z',
      window: 'M14 4h6v6M20 4l-9 9M10 4H5a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-5',
      pause: 'M8 5v14M16 5v14',
      power: 'M12 3v8M6.3 5.7a8 8 0 1 0 11.4 0',
      stop: 'M6 6h12v12H6Z',
      rebuild: 'M20 7v5h-5M20 12a8 8 0 1 0-2.3 5.7',
      expand: 'M4 9V4h5M4 4l6 6m10 5v5h-5m5 0-6-6',
      recovery: 'M12 3a9 9 0 1 0 9 9M12 7v5l3 3M16 3h5v5',
      trash: 'M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7M14 10v7',
      check: 'M5 12l5 5L20 7',
    };
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('class', 'action-icon');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', paths[icon]);
    svg.append(path);
    item.append(svg, el('span', 'action-label', label));
    return item;
  }

  function number(value, unit = '') {
    return typeof value === 'number' && Number.isFinite(value) ? `${value.toLocaleString('zh-CN', { maximumFractionDigits: 1 })}${unit}` : '—';
  }

  function vmById(id) { return state?.vms?.find((vm) => vm.id === id); }
  function sharesOf(vm) { return Array.isArray(vm?.shares) ? vm.shares : []; }
  function activeShares(vm) { return Array.isArray(vm?.active_shares) ? vm.active_shares : []; }
  function vmBusy(vm) { return Boolean(vm?.busy || busyVMs.has(vm?.id)); }
  function locked(vm) { return !connected || vmBusy(vm) || buildActive(); }
  function stateLabel(vm) { return vmBusy(vm) ? '操作中' : STATE_LABELS[vm.state] || '未知状态'; }
  function configKey(shares) {
    return JSON.stringify(shares.map((s) => ({ id: s.id || null, name: s.name, path: s.path, read_only: Boolean(s.read_only), enabled: Boolean(s.enabled) })));
  }
  function sharePayload(s) {
    const item = { name: s.name, path: s.path, read_only: Boolean(s.read_only), enabled: Boolean(s.enabled) };
    if (s.id) item.id = s.id;
    return item;
  }

  async function api(path, options = {}) {
    if (!token) throw new Error('尚未配置访问令牌，请从启动器打开授权链接。');
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeout || 20000);
    try {
      const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
      const init = { method: options.method || 'GET', headers, signal: controller.signal, cache: 'no-store', credentials: 'same-origin', redirect: 'error' };
      if (options.body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(options.body); }
      const response = await fetch(path, init);
      let result;
      try { result = await response.json(); } catch (_) { throw new Error('本机服务返回了无法识别的响应。请检查服务后重试。'); }
      if (!response.ok || result.ok !== true) {
        if (response.status === 401 || response.status === 403) {
          connected = false;
          lastError = '访问被拒绝，请检查访问令牌，并从本机启动器重新打开页面。';
          renderConnection();
        }
        throw new Error(typeof result.error === 'string' ? result.error : `操作未完成（HTTP ${response.status}）。`);
      }
      return result;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('请求等待超时。操作可能已被服务接收，请先刷新状态，不要重复执行强制操作。');
      if (error instanceof TypeError) throw new Error('无法连接本机服务，请确认管理器仍在运行。');
      throw error;
    } finally { clearTimeout(timeout); }
  }

  function toast(message, isError = false) {
    const item = el('div', `toast${isError ? ' error' : ''}`, message);
    $('toast-region').append(item);
    while ($('toast-region').children.length > 4) $('toast-region').firstElementChild.remove();
    setTimeout(() => item.remove(), isError ? 10000 : 6000);
  }

  function renderConnection() {
    $('connection-indicator').className = `connection-dot ${connected ? 'connected' : 'error'}`;
    $('connection-label').textContent = connected ? '本机服务已连接' : token ? '本机连接不可用' : '需要访问令牌';
    $('new-vm').disabled = !connected || !state?.capabilities?.offline_validate || buildActive();
    $('preinstall-new').disabled = !connected || !preinstallUI || buildActive();
    preinstallUI?.update();
    if (buildContext) updateBuildForm();
    if (growthContext) updateGrowthForm();
    if (confirmContext && ['action', 'remove'].includes(confirmContext.type)) $('confirm-submit').disabled = confirmBusy || buildActive();
    const banner = $('connection-banner');
    banner.hidden = connected;
    banner.replaceChildren();
    if (!connected) {
      banner.append(el('span', '', lastError || '未配置访问令牌。请从本机启动器打开授权链接，或手动连接。'));
      banner.append(button(token ? '重新连接 / 配置令牌' : '配置访问令牌', 'text-button', openToken));
      if (state) banner.append(el('span', '', ' 当前显示上次读取的状态，操作已暂时停用。'));
    }
  }

  function updateHeader() {
    const host = state.host || {};
    $('vm-total').textContent = String(VM_IDS.length).padStart(2, '0');
    $('host-cpu').textContent = number(host.cpu_count, ' 核');
    $('host-memory').textContent = number(host.memory_gib, ' GiB');
    $('host-disk').textContent = number(host.free_disk_gib, ' GiB');
    $('running-count').textContent = String(state.vms.filter((vm) => VM_IDS.includes(vm.id) && vm.state === 'running').length);
    $('app-version').textContent = state.app?.version ? `v${state.app.version}` : '';
  }

  function renderNavigation() {
    const nav = $('vm-navigation');
    nav.replaceChildren();
    VM_IDS.forEach((id) => {
      const vm = vmById(id);
      const item = button('', `nav-vm${selectedVM === id ? ' selected' : ''}`, () => selectVM(id), false, `nav-${id}`);
      item.setAttribute('aria-current', selectedVM === id ? 'true' : 'false');
      item.append(el('span', 'nav-symbol', '▤'), el('span', '', id));
      const dot = el('span', `nav-state ${vm?.state || ''}`);
      dot.setAttribute('aria-hidden', 'true');
      item.append(dot);
      item.setAttribute('aria-label', `${id}，${vm ? stateLabel(vm) : '等待状态'}`);
      nav.append(item);
    });
  }

  function renderSummaries() {
    const overview = $('vm-overview');
    overview.replaceChildren();
    VM_IDS.forEach((id) => {
      const vm = vmById(id);
      const item = button('', `vm-summary${selectedVM === id ? ' selected' : ''}`, () => selectVM(id), false, `summary-${id}`);
      item.setAttribute('aria-pressed', String(selectedVM === id));
      const top = el('div', 'summary-top');
      top.append(el('span', 'summary-symbol', '▤'), el('span', 'summary-title', id), el('span', `chip ${vm?.state || ''}`, vm ? stateLabel(vm) : '等待状态'));
      const bottom = el('div', 'summary-bottom');
      bottom.append(el('span', '', `${number(vm?.cpu)} 核 CPU`), el('span', 'divider'), el('span', '', `${number(vm?.memory_gib)} GiB 内存`), el('span', 'summary-arrow', selectedVM === id ? '↘' : '↗'));
      item.append(top, bottom);
      overview.append(item);
    });
  }

  function renderMachine(vm) {
    const panel = el('article', 'machine-panel');
    panel.setAttribute('aria-label', `${vm.id} 控制`);
    const head = el('div', 'machine-head');
    head.append(el('h2', '', vm.name || vm.id), el('span', `chip ${vm.state}`, stateLabel(vm)));
    panel.append(head);
    if (vmBusy(vm)) panel.append(el('div', 'machine-subtitle', `正在处理${ACTION_LABELS[vm.operation?.action || vm.operation] || '操作'}…`));
    else if (vm.setup_required) panel.append(el('span', 'setup-state', '待完成设置'));
    const resources = el('div', 'machine-resources');
    const capacity = Number.isSafeInteger(vm.disk_capacity_bytes) && vm.disk_capacity_bytes > 0
      ? ['磁盘容量', vm.disk_capacity_bytes / GIB, ' GiB'] : ['磁盘容量', vm.disk_gb, ' GB'];
    [['CPU', vm.cpu, ' 核'], ['内存', vm.memory_gib, ' GiB'], capacity].forEach(([label, value, unit]) => {
      const resource = el('div');
      const strong = el('strong', '', number(value));
      strong.append(el('small', '', unit));
      resource.append(el('span', '', label), strong);
      resources.append(resource);
    });
    panel.append(resources);
    const protection = el('div', 'protection-list');
    const network = vm.network || {};
    const firstSetup = vm.preinstalled?.first_setup_pending === true;
    if (network.normal_network) protection.append(el('span', 'protection-chip warning', '◇ 首次设置 · 普通网络，未过滤'));
    else if (firstSetup && vm.state !== 'running') protection.append(el('span', 'protection-chip warning', '◇ 首次设置将使用普通网络'));
    else protection.append(el('span', `protection-chip${network.protected ? '' : ' warning'}`, network.protected ? (vm.state === 'running' ? '◇ 网络规则已附加 · 待实测' : '◇ 保护启动器已配置') : '◇ 网络保护未确认'));
    if (network.blocked) protection.append(el('span', 'protection-chip warning', '网络阻断中 · 保持现状'));
    protection.append(el('span', 'protection-chip', network.management_enabled ? '管理通道已启用' : '管理通道未启用'));
    panel.append(protection);
    const actions = el('div', 'machine-actions');
    const starting = vm.preinstalled ? (firstSetup ? '首次设置启动…' : '受保护启动…') : vm.state === 'suspended' ? '继续运行' : '启动虚拟机';
    actions.append(actionButton(starting, 'play', 'button button-primary', () => vm.preinstalled ? openActionConfirm(vm.id, 'start') : runAction(vm.id, 'start'), locked(vm) || !(vm.preinstalled ? vm.state === 'stopped' : ['stopped', 'suspended'].includes(vm.state)), `start-${vm.id}`));
    actions.append(actionButton('打开窗口', 'window', `button ${vm.state === 'running' ? 'button-primary' : 'button-secondary'}`, () => runAction(vm.id, 'focus'), locked(vm) || vm.state !== 'running', `focus-${vm.id}`));
    const pauseAllowed = vm.state === 'running' && vm.pause_supported && activeShares(vm).length === 0;
    const pause = actionButton('暂停', 'pause', 'button button-secondary', () => runAction(vm.id, 'pause'), locked(vm) || !pauseAllowed, `pause-${vm.id}`);
    pause.title = activeShares(vm).length ? '本次启动存在共享目录，不支持暂停；请使用正常关机。' : !vm.pause_supported ? '当前环境不支持暂停。' : '保存运行状态，稍后继续';
    actions.append(pause);
    const shutdown = actionButton('正常关机', 'power', 'button button-secondary', () => openActionConfirm(vm.id, 'shutdown'), locked(vm) || vm.state !== 'running', `shutdown-${vm.id}`);
    shutdown.title = '发送关机请求，可能需要在虚拟机内确认。';
    actions.append(shutdown);
    panel.append(actions);
    const maintenance = el('div', 'maintenance-actions');
    if (firstSetup) maintenance.append(actionButton('标记首次设置完成…', 'check', 'button button-secondary', () => openActionConfirm(vm.id, 'finish-first-setup'), locked(vm), `finish-setup-${vm.id}`));
    if (vm.recovery_supported) maintenance.append(actionButton('恢复模式…', 'recovery', 'button button-secondary', () => openActionConfirm(vm.id, 'recovery-start'), locked(vm) || vm.state !== 'stopped', `recovery-${vm.id}`));
    if (canGrowDisk(vm)) maintenance.append(actionButton('扩容磁盘…', 'expand', 'button button-secondary', () => openGrowth(vm.id), false, `grow-${vm.id}`));
    if (vm.rebuild_supported) maintenance.append(actionButton('彻底重建…', 'rebuild', 'button button-secondary', () => openBuild(vm.id), locked(vm) || buildActive(), `rebuild-${vm.id}`));
    if (maintenance.childElementCount) panel.append(maintenance);
    const danger = el('div', 'danger-actions');
    danger.append(actionButton('强制停止…', 'stop', 'button button-danger-outline', () => openActionConfirm(vm.id, 'force-stop'), locked(vm) || vm.state !== 'running', `force-${vm.id}`));
    const removeVM = actionButton('删除 VM…', 'trash', 'button button-danger-outline vm-delete', () => openDelete(vm.id), locked(vm) || buildActive(), `delete-${vm.id}`);
    removeVM.title = '永久删除磁盘与配置；运行中的 VM 必须先正常关机。';
    danger.append(removeVM);
    if (vm.state === 'suspended') danger.append(actionButton('丢弃暂停状态…', 'trash', 'button button-danger-outline', () => openActionConfirm(vm.id, 'discard-state'), locked(vm), `discard-${vm.id}`));
    panel.append(danger);
    if (vm.state === 'suspended') panel.append(el('p', 'machine-notice', '共享变更需关机后重新启动才会生效。'));
    if (vm.preinstalled) {
      const imported = vm.preinstalled.configuration === 'imported';
      const manual = vm.preinstalled.configuration === 'manual_recovery_required';
      const installers = vm.preinstalled.installers_share === true;
      if (firstSetup && installers) panel.append(el('p', 'machine-notice', '首次设置使用普通网络，并在客机 Finder「My Shared Files」里挂只读文件夹 gold-installers。按里面「先读我.txt」用 Finder 安装 4 个应用、在 Clash Verge 导入节点并打开虚拟网卡模式；确认连上节点后关机，再点「标记首次设置完成」。之后每次都受保护启动。'));
      else if (firstSetup) panel.append(el('p', 'machine-notice', '首次设置使用普通网络，设置助理可以连上 Apple。进入桌面后确认 Clash Verge 已连上节点，再点「标记首次设置完成」；之后每次都受保护启动。'));
      if (!installers) panel.append(el('p', 'machine-notice', imported ? '客机报告：已导入配置。系统授权和连通性尚未验收。' : manual ? '客机报告：未覆盖已有资料，请在客机中检查配置。' : '私有配置已布置；首次登录后导入，尚无客机回执。'));
    }
    if (vm.state === 'missing') panel.append(el('p', 'machine-notice', '本机未找到这台虚拟机，请检查磁盘位置。'));
    if (vm.recovery_mode) panel.append(el('p', 'machine-notice', '恢复模式 · 不挂载宿主共享目录，请在客机内完成密码恢复。'));
    if (vm.last_error) panel.append(el('div', 'machine-error', typeof vm.last_error === 'string' ? vm.last_error : '最近一次操作失败，请查看本机服务记录。'));
    return panel;
  }

  function renderShares(vm) {
    if (vm.shares_locked) {
      const panel = el('article', 'shares-panel');
      panel.setAttribute('aria-label', `${vm.id} 共享目录已锁定`);
      const content = el('div', 'shares-empty');
      content.append(el('h2', '', '共享目录已锁定'), el('p', '', '这台 Ubuntu 虚拟机用于 DSH / Purge 测试。禁止共享宿主目录，剪贴板关闭，仅启用虚拟键盘和鼠标，未连接宿主 USB 存储设备。'), el('p', '', '允许公网模型服务，以及指定 GLM 接口；其他内网与宿主访问由虚拟机外的网络规则拦截。'));
      panel.append(content);
      return panel;
    }
    const panel = el('article', 'shares-panel');
    panel.setAttribute('aria-label', `${vm.id} 共享目录`);
    const heading = el('div', 'shares-heading');
    const headingText = el('div');
    headingText.append(el('h2', '', '共享目录'), el('p', '', `${sharesOf(vm).length} 个已配置 · ${activeShares(vm).length} 个本次启动挂载`));
    heading.append(headingText, button('＋ 添加目录', 'button button-secondary add-share', () => openShare(vm.id), locked(vm), `add-${vm.id}`));
    panel.append(heading);
    if (vm.pending_share_changes) {
      const pending = el('div', 'pending-banner');
      pending.append(el('strong', '', '◷ 目录配置等待下次冷启动'), el('span', '', vm.state === 'suspended' ? '恢复暂停不会更新共享目录。请先恢复并正常关机，再重新启动。' : vm.state === 'running' ? '请先在客机中正常关机，再重新启动。本次挂载保持不变。' : '下次启动时应用已保存的目录配置，不会自动启动。'));
      panel.append(pending);
    }
    const list = el('div', 'share-list');
    if (!sharesOf(vm).length) {
      const empty = el('div', 'shares-empty');
      const icon = el('div', 'empty-folder', '▱');
      icon.setAttribute('aria-hidden', 'true');
      empty.append(icon, el('h3', '', '添加你的项目目录'), el('p', '', '按需共享，读写权限由你决定。'), button('＋ 选择共享目录', 'button button-secondary', () => openShare(vm.id), locked(vm), `empty-add-${vm.id}`));
      list.append(empty);
    } else sharesOf(vm).forEach((share) => {
      const item = el('div', 'share-item');
      const row = el('div', 'share-row');
      const icon = el('span', 'folder-icon', '▱');
      icon.setAttribute('aria-hidden', 'true');
      const info = el('div', 'share-info');
      const name = el('div', 'share-name-row');
      name.append(el('span', 'share-name', share.name), el('span', `mode-chip ${share.read_only ? '' : 'rw'}`, share.read_only ? '只读' : '读写'));
      if (!share.enabled) name.append(el('span', 'mode-chip disabled', '已停用'));
      info.append(name, el('p', 'share-path', share.path), el('p', 'guest-path', `客机 /Volumes/My Shared Files/${share.name}`));
      const active = activeShares(vm).find((s) => s.id === share.id);
      const matches = active && active.path === share.path && Boolean(active.read_only) === Boolean(share.read_only) && active.name === share.name && share.enabled;
      let status = vm.state === 'stopped' ? '下次启动挂载' : matches ? '本次启动已挂载' : '本次启动未按此配置挂载';
      if (!share.enabled) status = active ? '下次冷启动停用 · 本次仍挂载' : '配置已停用';
      info.append(el('div', `active-status${vm.pending_share_changes ? ' pending' : ''}`, status));
      row.append(icon, info);
      item.append(row);
      const tools = el('div', 'share-tools');
      tools.append(button('在 Finder 中显示', 'text-button', () => revealDirectory(vm.id, share.id), locked(vm), `reveal-${share.id}`));
      tools.append(button('编辑', 'text-button', () => openShare(vm.id, share.id), locked(vm), `edit-${share.id}`));
      tools.append(button(share.enabled ? '停用' : '启用', 'text-button', () => toggleShare(vm.id, share.id), locked(vm), `toggle-${share.id}`));
      tools.append(button('移除', 'text-button remove', () => openRemove(vm.id, share.id), locked(vm), `remove-${share.id}`));
      item.append(tools);
      list.append(item);
    });
    panel.append(list);
    const footer = el('div', 'shares-footer');
    footer.append(el('p', '', '↳ 客机目录：/Volumes/My Shared Files/<共享名称>'), el('p', '', '移除或停用共享不会删除主机文件。'));
    if (activeShares(vm).some((active) => !sharesOf(vm).some((s) => s.id === active.id))) footer.append(el('p', '', '注意：已移除的旧目录在本次启动中仍可能挂载，正常关机后才会解除。'));
    panel.append(footer);
    return panel;
  }

  function renderActivity() {
    const list = $('activity-list');
    list.replaceChildren();
    const events = Array.isArray(state?.events) ? state.events.slice(0, 6) : [];
    if (!events.length) { list.append(el('p', 'empty-inline', '尚无操作记录。你的下一次操作会显示在这里。')); return; }
    events.forEach((event) => {
      const item = el('div', 'activity-item');
      const message = el('div', 'activity-message');
      if (event.vm) message.append(el('span', 'activity-vm', event.vm));
      message.append(el('span', '', event.message || ACTION_LABELS[event.action] || '状态更新'));
      const when = new Date(event.time);
      const time = el('time', 'activity-time', Number.isNaN(when.getTime()) ? '时间未知' : when.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }));
      if (!Number.isNaN(when.getTime())) time.dateTime = when.toISOString();
      item.append(el('span', `event-dot ${event.level === 'error' ? 'error' : ''}`), message, time);
      list.append(item);
    });
  }

  function render(force = false) {
    const signature = JSON.stringify([state, selectedVM, connected, lastError, Boolean(token), [...busyVMs]]);
    if (!force && signature === renderedSignature) return;
    renderedSignature = signature;
    const focused = document.activeElement?.dataset?.focusKey;
    renderNavigation();
    renderSummaries();
    if (state) {
      updateHeader();
      const vm = vmById(selectedVM);
      const detail = $('workspace-detail');
      if (vm) detail.replaceChildren(renderMachine(vm), renderShares(vm));
      else {
        const missing = el('div', 'loading-panel');
        missing.append(el('h2', '', `${selectedVM} 暂无状态`), el('p', '', '服务未返回这台虚拟机的信息，相关操作不可用。'));
        detail.replaceChildren(missing);
      }
      renderActivity();
      renderBuildJob();
    } else if (!token || lastError) {
      const waiting = el('div', 'loading-panel');
      waiting.append(el('h2', '', token ? '暂时无法连接本机服务' : '为你的本地工作空间授权'), el('p', '', token ? '未连接时不显示推测状态，也不会执行虚拟机操作。' : '从启动器打开授权链接，或输入访问令牌开始管理。'), button(token ? '检查连接' : '连接本机服务', 'button button-primary', token ? () => refresh(true) : openToken));
      $('workspace-detail').replaceChildren(waiting);
    }
    renderConnection();
    if (deleteContext && !deleteBusy) updateDeleteForm();
    if (focused && !document.activeElement?.closest('dialog')) {
      const next = [...document.querySelectorAll('[data-focus-key]')].find((item) => item.dataset.focusKey === focused && !item.disabled);
      if (next) next.focus({ preventScroll: true });
    }
  }

  function selectVM(id) { selectedVM = id; render(); }

  async function refresh(userInitiated = false) {
    if (pollFlight) return pollFlight;
    if (!token) { connected = false; renderConnection(); return; }
    $('refresh').disabled = true;
    pollFlight = (async () => {
      try {
        const result = await api('/api/state');
        if (!Array.isArray(result.vms)) throw new Error('本机服务未返回有效的虚拟机状态。');
        state = result;
        VM_IDS = result.vms.map((v) => v.id);
        if (!VM_IDS.includes(selectedVM)) selectedVM = VM_IDS[0] || '';
        connected = true;
        lastError = '';
        $('last-sync').textContent = `同步于 ${new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })}`;
        render();
      } catch (error) {
        connected = false;
        lastError = error.message;
        $('last-sync').textContent = state ? '上次状态 · 未连接' : '尚未同步';
        render();
        if (userInitiated) toast(error.message, true);
      } finally { $('refresh').disabled = false; pollFlight = null; }
    })();
    return pollFlight;
  }

  async function runAction(id, action, confirmName, backendAcknowledged = false, firstSetup = false) {
    lastActionError = '';
    const vm = vmById(id);
    if (!vm || locked(vm)) {
      toast('虚拟机状态已变化或正在操作，请等待状态更新。', true);
      return false;
    }
    if (action === 'recovery-start' && (!vm.recovery_supported || vm.state !== 'stopped' || confirmName !== id)) {
      toast('恢复启动仅适用于支持恢复模式且已关机的虚拟机，并须在对话框里确认。', true);
      return false;
    }
    if (action === 'start' && vm.preinstalled) {
      const pending = vm.preinstalled.first_setup_pending === true;
      const consented = pending ? firstSetup && !backendAcknowledged : backendAcknowledged && !firstSetup;
      if (!consented || confirmName !== id || vm.state !== 'stopped') {
        toast(pending ? '请在首次设置对话框里确认使用普通网络。' : '请在受保护启动对话框里确认后端提示。', true);
        return false;
      }
    }
    busyVMs.add(id);
    render();
    try {
      const body = { action };
      if (confirmName !== undefined) body.confirm_name = confirmName;
      if (action === 'start' && vm.preinstalled && firstSetup) body.first_setup_normal_network = true;
      else if (action === 'start' && vm.preinstalled && backendAcknowledged) body.acknowledge_reviewed_unsigned_backend = true;
      const result = await api(`/api/vms/${encodeURIComponent(id)}/action`, { method: 'POST', body });
      toast(result.message || '请求已发送，请等待虚拟机状态更新。');
      await refresh();
      return true;
    } catch (error) {
      lastActionError = error.message;
      toast(error.message, true);
      return false;
    } finally { busyVMs.delete(id); render(); }
  }

  function mountGrowth() {
    $('growth-target').addEventListener('input', updateGrowthForm);
    $('growth-form').addEventListener('submit', (event) => event.preventDefault());
    $('growth-submit').addEventListener('click', submitGrowth);
    $('growth-dialog').addEventListener('cancel', (event) => { if (growthContext?.pending) event.preventDefault(); });
    $('growth-dialog').addEventListener('close', () => { growthContext = null; });
  }

  function canGrowDisk(vm) {
    return vm?.disk_growth_supported === true && vm.id === selectedVM && vm.state === 'stopped' && !locked(vm) &&
      Number.isSafeInteger(vm.disk_capacity_bytes) && vm.disk_capacity_bytes > 0 && vm.disk_capacity_bytes < 1024 * GIB;
  }

  function openGrowth(id) {
    const vm = vmById(id);
    if (growthContext || !canGrowDisk(vm)) return;
    const bytes = vm.disk_capacity_bytes;
    growthContext = { id, bytes, pending: false, blocker: '' };
    $('growth-title').textContent = `扩容磁盘 · ${id}`;
    const allocated = number(vm.allocated_gb, ' GB');
    $('growth-current').textContent = `当前虚拟磁盘容量：${number(bytes / GIB, ' GiB')}（${bytes} 字节）。宿主已分配空间：${allocated}，不是虚拟磁盘容量，也不是客机剩余空间。`;
    $('growth-target').value = '';
    $('growth-dialog').showModal(); updateGrowthForm(); $('growth-target').focus();
  }

  function updateGrowthForm() {
    const ctx = growthContext;
    if (!ctx) return;
    const vm = vmById(ctx.id), input = $('growth-target');
    if (!ctx.pending && !ctx.blocker && (!canGrowDisk(vm) || vm.disk_capacity_bytes !== ctx.bytes)) {
      ctx.blocker = '所选 VM、磁盘容量或操作状态已变化。请关闭并重新打开扩容对话框，核对当前容量。';
    }
    const target = Number(input.value);
    const invalid = !/^\d+$/.test(input.value) || target < 30 || target > 1024 ? '请输入 30–1024 GiB 范围内的整数总容量。' :
      target * GIB <= ctx.bytes ? `只能扩大磁盘：目标总容量至少为 ${Math.max(30, Math.floor(ctx.bytes / GIB) + 1)} GiB。` : '';
    const message = ctx.blocker || invalid;
    $('growth-error').textContent = message; $('growth-error').hidden = !message;
    input.disabled = ctx.pending || Boolean(ctx.blocker);
    input.setAttribute('aria-invalid', String(Boolean(invalid)));
    $('growth-cancel').disabled = ctx.pending;
    $('growth-submit').disabled = ctx.pending || Boolean(message);
    $('growth-submit').textContent = ctx.pending ? '正在核对扩容结果…' : invalid ? '确认扩容' : `确认扩容至 ${target} GiB`;
  }

  async function submitGrowth() {
    const ctx = growthContext;
    if (!ctx || ctx.pending || !$('growth-dialog').open) return;
    updateGrowthForm();
    if ($('growth-submit').disabled) return;
    const target = Number($('growth-target').value);
    ctx.pending = true; busyVMs.add(ctx.id); updateGrowthForm(); render();
    let success = false;
    try {
      await api(`/api/vms/${encodeURIComponent(ctx.id)}/expand-disk`, { method: 'POST',
        body: { target_gib: target, expected_bytes: ctx.bytes, acknowledge_growth: true } });
      success = true;
    } catch (error) {
      ctx.blocker = `${error.message} 请关闭此窗口，核对最新磁盘容量后再决定是否重新扩容。`;
    } finally {
      // A poll started before the POST cannot confirm its outcome. Never update capacity optimistically or retry a POST.
      if (pollFlight) await pollFlight;
      await refresh(true);
      ctx.pending = false; busyVMs.delete(ctx.id);
      if (success) {
        $('growth-dialog').close();
        toast(`${ctx.id} 的虚拟磁盘已扩容至 ${target} GiB。请在客机内检查分区和可用空间。`);
      }
      updateGrowthForm(); render();
    }
  }

  function openActionConfirm(id, action) {
    const vm = vmById(id);
    if (!vm || locked(vm)) return;
    if (action === 'recovery-start' && (!vm.recovery_supported || vm.state !== 'stopped')) return;
    const firstSetup = action === 'start' && vm.preinstalled?.first_setup_pending === true;
    const backend = action === 'start' && Boolean(vm.preinstalled) && !firstSetup;
    if ((backend || firstSetup) && vm.state !== 'stopped') return;
    if (action === 'finish-first-setup' && vm.preinstalled?.first_setup_pending !== true) return;
    const dangerous = backend || firstSetup || action === 'force-stop' || action === 'discard-state' || action === 'recovery-start';
    // One click in the dialog confirms; the request still names this exact VM.
    confirmContext = { type: 'action', id, action, dangerous, backend, firstSetup };
    $('confirm-title').textContent = `${ACTION_LABELS[action]} ${id}？`;
    const installersNote = vm.preinstalled?.installers_share === true
      ? '客机 Finder 的「My Shared Files」里会出现只读文件夹 gold-installers，装着 4 个应用、节点配置和说明：用 Finder 把应用拖进「应用程序」，在 Clash Verge 导入节点并打开虚拟网卡模式，确认已经连上节点后关机，再点「标记首次设置完成」。之后每次启动都走受保护启动，这个文件夹也不再出现。'
      : '进入桌面后，Clash Verge 会自动导入节点；按提示授权它的服务，确认已经连上节点后，再点「标记首次设置完成」。之后每次启动都走受保护启动。';
    $('confirm-description').textContent = firstSetup ? '首次设置使用普通网络：这次启动不经过网络过滤，客机直接使用本机网络，Apple 等服务会看到本机的真实 IP；这样设置助理才能连上 Apple。不运行网络后端，也不需要后端授权。' + installersNote : action === 'finish-first-setup' ? '请先在客机里确认 Clash Verge 已连上节点。标记后，之后每次启动都走受保护启动：客机只能连到你的 VPN 节点，Clash 没连上时客机没有网络。此标记不能撤销；如果 VM 正在运行，这次运行仍是普通网络，关机后生效。' : backend ? '网络后端 gvproxy 取自 Podman 官方安装包（Red Hat 签名、经 Apple 公证、固定 SHA-256），不安装 Podman。点击「同意尝试受保护启动」，即允许仅为本机这份私有副本设置所有者执行位，并请求 macOS 正常执行。较早预装的 VM 会先换用这份签名版后端并更新受保护启动文件，首次可能需要下载约 77 MB；磁盘和网络过滤规则不变。不会清除隔离属性或关闭系统保护；如被 macOS 拒绝则不启动，也不改用普通网络。首次系统设置、账号及服务授权仍需亲自完成。' : action === 'recovery-start' ? '仅为找回这台虚拟机遗忘的本地登录密码而进入 macOS 恢复模式。保留现有磁盘、数据与 VM 身份，不创建新身份，不抹除、不重建，也不清除钥匙串。本次恢复启动挂载的宿主共享目录为零。你需要亲自在虚拟机窗口内完成恢复，可能需要 FileVault 恢复密钥或 Apple Account。不要向模型提供任何密码、恢复密钥或账号凭据。此操作仅启动恢复模式，不保证能重设密码。' : action === 'shutdown' ? '向客机发送正常关机请求，不会强制终止进程。客机可能弹出确认窗口，请在虚拟机内完成确认；发送请求不等于已关机。' : action === 'force-stop' ? '将立即终止虚拟机，未保存的工作可能永久丢失。请优先使用正常关机。此操作不会删除虚拟机或主机共享目录。' : '将丢弃保存的运行状态，暂停时未保存的工作可能永久丢失。此操作不会删除虚拟机磁盘或主机共享目录；随后需重新启动。';
    $('confirm-submit').textContent = firstSetup ? '用普通网络启动首次设置' : backend ? '同意尝试受保护启动' : ACTION_LABELS[action];
    $('confirm-submit').className = dangerous ? 'button button-danger' : 'button button-primary';
    $('confirm-submit').disabled = false;
    $('confirm-error').hidden = true;
    $('confirm-dialog').showModal();
  }

  function openRemove(id, shareId) {
    const vm = vmById(id);
    const share = sharesOf(vm).find((s) => s.id === shareId);
    if (!share || locked(vm)) return;
    confirmContext = { type: 'remove', id, shareId, baseKey: configKey(sharesOf(vm)) };
    $('confirm-title').textContent = '移除共享目录？';
    $('confirm-description').textContent = `仅从 ${id} 的共享配置中移除「${share.name}」。不会删除主机目录或其中的文件。运行或暂停期间，原挂载会持续到下次冷启动。`;
    $('confirm-submit').textContent = '仅移除共享';
    $('confirm-submit').className = 'button button-primary';
    $('confirm-submit').disabled = false;
    $('confirm-error').hidden = true;
    $('confirm-dialog').showModal();
  }

  async function saveShares(id, shares, baseKey, acknowledgeWrite = false) {
    const vm = vmById(id);
    if (!vm || locked(vm)) throw new Error('虚拟机正在操作或连接不可用，请稍后重试。');
    if (configKey(sharesOf(vm)) !== baseKey) throw new Error('共享配置已被其他操作更新。请关闭并重新打开此对话框，以免覆盖新配置。');
    busyVMs.add(id);
    render();
    try {
      const body = { shares: shares.map(sharePayload) };
      if (acknowledgeWrite) body.acknowledge_write = true;
      const result = await api(`/api/vms/${encodeURIComponent(id)}/shares`, { method: 'POST', body });
      // Apply the authoritative save response immediately; polling never touches open form fields.
      if (Array.isArray(result.shares)) vm.shares = result.shares;
      if (typeof result.pending_share_changes === 'boolean') vm.pending_share_changes = result.pending_share_changes;
      toast(result.message || '共享配置已保存，不会自动重启虚拟机。');
      await refresh();
      return result;
    } finally { busyVMs.delete(id); render(); }
  }

  async function toggleShare(id, shareId) {
    const vm = vmById(id);
    if (!vm || locked(vm)) return;
    const shares = sharesOf(vm);
    const target = shares.find((s) => s.id === shareId);
    // Re-enabling write access deserves a fresh, explicit acknowledgement too.
    if (target && !target.enabled && !target.read_only) {
      openShare(id, shareId);
      $('share-enabled').checked = true;
      updateShareForm();
      return;
    }
    try { await saveShares(id, shares.map((s) => s.id === shareId ? { ...s, enabled: !s.enabled } : s), configKey(shares)); }
    catch (error) { toast(error.message, true); }
  }

  function openShare(id, shareId = null) {
    const vm = vmById(id);
    if (!vm || locked(vm)) return;
    const share = sharesOf(vm).find((s) => s.id === shareId);
    if (shareId && !share) return;
    shareContext = { id, shareId, original: share ? { ...share } : null, shares: sharesOf(vm).map((s) => ({ ...s })), baseKey: configKey(sharesOf(vm)), pickerPending: false };
    $('share-title').textContent = share ? '编辑共享目录' : '添加共享目录';
    $('share-description').textContent = `为 ${id} 配置主机目录。不会创建、移动或删除主机文件。`;
    $('share-name').value = share?.name || '';
    $('share-path').value = share?.path || '';
    $('share-mode').value = share && !share.read_only ? 'rw' : 'ro';
    $('share-enabled').checked = share ? Boolean(share.enabled) : true;
    $('write-ack').checked = false;
    $('share-form-error').hidden = true;
    $('pick-directory').hidden = !state?.capabilities?.native_picker;
    $('picker-hint').textContent = state?.capabilities?.native_picker ? '原生选择器只会在点击后打开；也可以手动填写绝对路径。' : '当前服务不支持原生选择器，请手动填写已存在的主机绝对目录路径。';
    setShareBusy(false);
    $('pick-directory').disabled = nativePickerBusy;
    $('pick-directory').textContent = nativePickerBusy ? '已有选择器打开…' : '选择目录…';
    updateShareForm();
    $('share-dialog').showModal();
  }

  function needsWriteAck() {
    if ($('share-mode').value !== 'rw') return false;
    const original = shareContext?.original;
    return !original || Boolean(original.read_only) || original.path !== $('share-path').value || original.name !== $('share-name').value.trim() || (!original.enabled && $('share-enabled').checked);
  }

  function updateShareForm() {
    const name = $('share-name').value.trim();
    $('guest-path-preview').textContent = `/Volumes/My Shared Files/${name || '…'}`;
    $('write-warning').hidden = $('share-mode').value !== 'rw';
    $('write-ack').required = needsWriteAck();
    $('share-submit').disabled = dialogBusy || Boolean(shareContext?.pickerPending) || (needsWriteAck() && !$('write-ack').checked);
  }

  function setShareBusy(value) {
    dialogBusy = value;
    ['share-name', 'share-path', 'share-mode', 'share-enabled', 'write-ack', 'pick-directory'].forEach((id) => { $(id).disabled = value; });
    $('pick-directory').disabled = value || nativePickerBusy;
    $('share-submit').textContent = value ? '正在保存…' : '保存目录';
    $('share-submit').disabled = value;
    $('share-dialog').querySelectorAll('.dialog-close').forEach((item) => { item.disabled = value; });
  }

  async function pickDirectory() {
    const context = shareContext;
    if (!context || nativePickerBusy || context.pickerPending || dialogBusy) return;
    nativePickerBusy = true;
    context.pickerPending = true;
    $('pick-directory').disabled = true;
    $('pick-directory').textContent = '等待选择…';
    updateShareForm();
    try {
      const result = await api('/api/pick-directory', { method: 'POST', body: { vm: context.id }, timeout: 300000 });
      if (shareContext !== context || !$('share-dialog').open) return;
      if (!result.cancelled && typeof result.path === 'string') {
        $('share-path').value = result.path;
        $('write-ack').checked = false;
        if (!$('share-name').value.trim()) $('share-name').value = result.path.split('/').filter(Boolean).pop() || '';
      }
    } catch (error) {
      if (shareContext === context && $('share-dialog').open) showError('share-form-error', error.message);
      else toast(error.message, true);
    } finally {
      nativePickerBusy = false;
      context.pickerPending = false;
      $('pick-directory').disabled = dialogBusy;
      $('pick-directory').textContent = '选择目录…';
      updateShareForm();
    }
  }

  function showError(id, message) { $(id).textContent = message; $(id).hidden = false; }

  async function submitShare(event) {
    event.preventDefault();
    const context = shareContext;
    if (!context || dialogBusy || context.pickerPending) return;
    const name = $('share-name').value.trim();
    const path = $('share-path').value;
    const readOnly = $('share-mode').value === 'ro';
    if (!name || name.includes('/') || name.includes(':') || /[\r\n]/.test(name)) { showError('share-form-error', '请输入有效的共享名称，不包含斜线、冒号或换行。'); $('share-name').focus(); return; }
    if (!path.startsWith('/') || /[:\r\n]/.test(path)) { showError('share-form-error', '请填写主机上的绝对目录路径，不包含冒号或换行。'); $('share-path').focus(); return; }
    if (context.shares.some((s) => s.id !== context.shareId && s.name === name)) { showError('share-form-error', '这台虚拟机已有同名共享，请使用不同名称。'); return; }
    const acknowledge = needsWriteAck();
    if (acknowledge && !$('write-ack').checked) { showError('share-form-error', '请先勾选读写权限风险确认。'); return; }
    const share = { name, path, read_only: readOnly, enabled: $('share-enabled').checked };
    if (context.shareId) share.id = context.shareId;
    const shares = context.shareId ? context.shares.map((s) => s.id === context.shareId ? share : s) : [...context.shares, share];
    setShareBusy(true);
    $('share-form-error').hidden = true;
    try {
      await saveShares(context.id, shares, context.baseKey, acknowledge);
      $('share-dialog').close();
    } catch (error) { showError('share-form-error', error.message); }
    finally { setShareBusy(false); updateShareForm(); }
  }

  function openArchiveJob(job) {
    const interruptedDownload = job?.phase === 'interrupted' && job.published === false && job.interrupted_download_archivable === true;
    if (!connected || !job || job.mode !== 'preinstall' || !(interruptedDownload || (job.phase === 'failed' && job.recovery_required === true))
      || job.published === true || typeof job.id !== 'string' || typeof job.name !== 'string' || !job.name) return;
    confirmContext = { type: 'archive-job', id: job.name, jobId: job.id };
    $('confirm-title').textContent = `归档${interruptedDownload ? '已中断的下载' : '失败任务'} ${job.name}？`;
    $('confirm-description').textContent = interruptedDownload
      ? '这次下载进程已退出，尚未创建虚拟磁盘。仅归档这条任务记录，不删除共享下载缓存，不影响同名 VM，也不会重试。'
      : `仅归档此任务，不停止其他任务，不清理下载缓存。不会删除、移动、续接或发布暂存盘：它仍保留在 ~/.tart/.gold-manager-staging/${job.id}。`;
    $('confirm-submit').textContent = interruptedDownload ? '归档已中断的下载' : '归档失败任务';
    $('confirm-submit').className = 'button button-danger';
    $('confirm-submit').disabled = false;
    $('confirm-error').hidden = true;
    $('confirm-dialog').showModal();
  }

  async function submitConfirm(event) {
    event.preventDefault();
    const context = confirmContext;
    if (!context || confirmBusy) return;
    confirmBusy = true;
    $('confirm-submit').disabled = true;
    $('confirm-dialog').querySelectorAll('.dialog-close').forEach((item) => { item.disabled = true; });
    $('confirm-error').hidden = true;
    try {
      if (context.type === 'action') {
        const done = await runAction(context.id, context.action, context.dangerous ? context.id : undefined, context.backend === true, context.firstSetup === true);
        if (!done) { showError('confirm-error', lastActionError || '操作未完成，请刷新状态后核对；不要重复执行危险操作。'); return; }
      } else if (context.type === 'archive-job') {
        await api('/api/preinstall/archive', { method: 'POST', body: { job_id: context.jobId, confirm_name: context.id } });
        toast('已归档失败任务；暂存盘仍保留，可以用新名称重新预装。');
        await refresh(true);
      } else {
        const vm = vmById(context.id);
        await saveShares(context.id, sharesOf(vm).filter((s) => s.id !== context.shareId), context.baseKey);
      }
      $('confirm-dialog').close();
    } catch (error) { showError('confirm-error', error.message); }
    finally {
      confirmBusy = false;
      $('confirm-submit').disabled = false;
      $('confirm-dialog').querySelectorAll('.dialog-close').forEach((item) => { item.disabled = false; });
    }
  }

  async function revealDirectory(id, shareId) {
    try { await api('/api/reveal-directory', { method: 'POST', body: { vm: id, share_id: shareId } }); }
    catch (error) { toast(error.message, true); }
  }


  function mountSetupProfile(prefix) {
    const box = el('fieldset', 'setup-profile');
    box.append(el('legend', '', '自动初始化模板 · 预览'));
    const addSelect = (key, label, options) => {
      const field = el('div', 'field');
      const caption = el('label', '', label);
      caption.htmlFor = `${prefix}-${key}`;
      const select = el('select');
      select.id = `${prefix}-${key}`;
      options.forEach(([value, name]) => { const option = el('option', '', key === 'timezone' ? `${name} · ${value}` : name); option.value = value; select.append(option); });
      if (key === 'country') select.addEventListener('change', () => {
        const recommendations = { US: 'America/Los_Angeles', GB: 'Europe/London', JP: 'Asia/Tokyo', SG: 'Asia/Singapore', DE: 'Europe/Berlin', CA: 'America/Toronto', AU: 'Australia/Sydney', FR: 'Europe/Paris', NL: 'Europe/Amsterdam', HK: 'Asia/Hong_Kong' };
        const timezone = $(`${prefix}-timezone`);
        if (recommendations[select.value]) timezone.value = recommendations[select.value];
      });
      field.append(caption, select); box.append(field);
    };
    addSelect('language', '客机界面语言（默认 English US）', SETUP_LANGUAGES);
    addSelect('country', '国家 / 地区（可按 VPS 所在国家选择）', SETUP_COUNTRIES);
    addSelect('timezone', '城市 / IANA 时区（国家推荐后可手动更改）', SETUP_TIMEZONES);
    const location = el('label', 'checkbox-label');
    const input = el('input'); input.type = 'checkbox'; input.id = `${prefix}-location`;
    location.append(input, el('span', '', '启用客机定位服务（默认关闭）')); box.append(location);
    box.append(el('p', 'form-note', '国家 / 地区不是城市或时区：请按 VPS 实际所在国家选择。每次更改国家会推荐一个默认时区，你仍可手动覆盖城市 / IANA 时区；不会改变界面语言。美国、加拿大、澳大利亚有多个时区，必须核对 VPS 所在城市，不能只看国家。不会依据 IP 自动推断，也不改变 VPS 或网络出口。默认跳过迁移、Apple Account 与可选设置，不共享分析数据。此模板不是完成状态；自动化遇到未知页面会停止，仍需在原生 App 确认。'));
    $(`${prefix}-setup-profile`).replaceChildren(box);
  }

  function readSetupProfile(prefix) {
    const language = $(`${prefix}-language`).value;
    const country = $(`${prefix}-country`).value;
    const timezone = $(`${prefix}-timezone`).value;
    if (!SETUP_LANGUAGES.some(([id]) => id === language) || !SETUP_COUNTRIES.some(([id]) => id === country) || !SETUP_TIMEZONES.some(([id]) => id === timezone)) throw new Error('初始化模板选项无效，请重新选择。');
    return { version: 1, language, country, timezone, location_services: $(`${prefix}-location`).checked, skip_migration: true, skip_apple_account: true, share_analytics: false };
  }

  function setSetupProfile(prefix, profile = {}) {
    [['language', SETUP_LANGUAGES], ['country', SETUP_COUNTRIES], ['timezone', SETUP_TIMEZONES]].forEach(([key, options]) => {
      $(`${prefix}-${key}`).value = options.some(([id]) => id === profile[key]) ? profile[key] : options[0][0];
    });
    $(`${prefix}-location`).checked = profile.location_services === true;
  }

  function nativeInitializationBridge() {
    const bridge = window.webkit?.messageHandlers?.startGuestInitialization;
    return typeof bridge?.postMessage === 'function' ? bridge : null;
  }

  function openInitialize(id) {
    const vm = vmById(id);
    if (!vm || locked(vm) || !vm.setup_required || vm.state !== 'running' || vm.recovery_mode) return;
    initializeContext = { id };
    setSetupProfile('initialize', vm.setup_profile || {});
    $('initialize-title').textContent = `自动初始化 ${id} · 预览`;
    $('initialize-native-note').textContent = nativeInitializationBridge() ? '继续后由原生 App 显示安全凭据表单；提交请求不代表初始化完成。' : '请在原生 App 使用：当前浏览器没有安全初始化桥接，不能执行自动初始化。';
    $('initialize-submit').disabled = !nativeInitializationBridge();
    $('initialize-error').hidden = true;
    $('initialize-dialog').showModal();
  }

  function updateDeleteForm() {
    const vm = vmById(deleteContext?.id);
    $('delete-submit').disabled = deleteBusy || !vm || locked(vm) || buildActive() || !['stopped', 'suspended'].includes(vm.state);
  }

  function openDelete(id) {
    const vm = vmById(id);
    if (!vm || locked(vm) || buildActive()) return;
    deleteContext = { id };
    $('delete-form').reset();
    $('delete-title').textContent = `永久删除 ${id}？`;
    $('delete-error').hidden = true;
    if (!['stopped', 'suspended'].includes(vm.state)) showError('delete-error', '这台 VM 必须先正常关机后才能删除。请取消并在客机内完成关机；不会自动强制停止。');
    updateDeleteForm();
    $('delete-dialog').showModal();
  }

  function buildActive() {
    const job = state?.build_job;
    return Boolean((typeof preinstallBusy !== 'undefined' && preinstallBusy) || job?.recovery_required || job?.offline_preinstall?.active || job?.vpn_configuration?.active
      || (job?.mode === 'preinstall' && !job.published && ['awaiting_offline_preinstall', 'awaiting_first_desktop_acceptance'].includes(job.phase)))
      || ['queued', 'preflight', 'downloading', 'inspecting', 'acquiring', 'installing', 'awaiting_vpn_configuration', 'vpn_resume_queued', 'resuming_vpn', 'preparing_runtime', 'publishing', 'provisioning', 'committing', 'deleting'].includes(job?.phase);
  }

  function waitingVpnJob() {
    const job = state?.build_job;
    return window.GoldPreinstall?.isWaitingVpnJob(job) ? job : null;
  }

  function openWaitingVpnConfiguration(id, name) {
    const job = waitingVpnJob();
    if (!connected || preinstallBusy || !job || job.id !== id || job.name !== name) return;
    return preinstallUI?.openResume(id);
  }

  function renderBuildJob() {
    const job = state?.build_job;
    const region = $('build-job');
    const awaitingSetup = job?.phase === 'awaiting_user_setup' && !job.recovery_required;
    // The selected VM already carries a short setup-state badge. Do not repeat
    // an entire completed-install notice above its controls on every refresh.
    region.hidden = !job || (awaitingSetup && job.name === selectedVM);
    region.classList.toggle('build-job-compact', Boolean(awaitingSetup));
    region.replaceChildren();
    if (region.hidden) return;
    if (awaitingSetup) {
      region.append(el('strong', '', `${job.name} 已创建 · 待完成设置`), button('查看 VM', 'text-button', () => selectVM(job.name)));
      return;
    }
    const labels = { queued: '已排队', preflight: '前置检查', downloading: '下载恢复镜像', inspecting: '检查镜像', installing: '离线安装系统', provisioning: '准备软件与防护', committing: '发布新环境', awaiting_user_setup: '等待客机初始设置', failed: '任务未完成', interrupted: '任务已中断' };
    labels.awaiting_offline_preinstall = '系统已恢复 · 应用未预装 · 未启动';
    labels.awaiting_first_desktop_acceptance = '未启动 · 待首次设置';
    labels.deleted = '已删除';
    labels.deleting = '正在删除';
    Object.assign(labels, { acquiring: '获取经审核原始材料',
      awaiting_vpn_configuration: '系统已恢复 · 等待配置 VPN', vpn_resume_queued: '继续配置 VPN 已排队', resuming_vpn: '继续配置 VPN',
      preparing_runtime: '准备首次设置文件夹与受保护启动', publishing: '发布新 VM · 不自动启动' });
    const materialFailure = job.mode === 'preinstall' && job.phase === 'failed' && job.failed_phase === 'acquiring' && job.system_restored === false;
    let message = job.message || '';
    if (materialFailure) {
      labels.failed = '材料准备失败';
      message = (['unsafe-tar-path', 'invalid-tart-license-member'].includes(job.failure_code) ? 'Tart 安装包的路径未通过检查。' : '原始材料下载或校验未完成。') + '尚未创建虚拟磁盘。已保留下载，不自动重试。';
    }
    region.append(el('strong', '', `${job.mode === 'preinstall' ? '一键预装' : job.mode === 'offline_validate' ? '仅安装 VM' : job.mode === 'delete' ? '删除' : job.mode === 'rebuild' ? '重建' : '新建'} ${job.name || ''} · ${labels[job.phase] || job.phase}`), el('span', '', message));
    const own = (map, key) => typeof key === 'string' && Object.prototype.hasOwnProperty.call(map, key);
    if (materialFailure) {
      // Fixed product keys and cause codes only; the backend never forwards network text.
      const products = { ccbaga: 'CCBaga', clashVergeRev: 'Clash Verge', claudeDesktop: 'Claude Desktop' };
      const causes = {
        'download-timeout': '30 秒内没有收到服务器的响应或数据（网络停滞或被阻断）。',
        'download-connection-lost': '下载途中连接被中断。',
        'download-connect-failed': '无法连接下载服务器。',
        'download-dns-failed': '无法解析下载服务器的地址。',
        'download-tls-failed': '与下载服务器的安全连接（TLS）失败，可能是代理或证书问题。',
        'download-network-unreachable': '网络不可达。',
        'download-protocol-error': '下载服务器的响应格式异常。',
        'download-deadline-exceeded': '下载超过单个文件的总时限。',
        'truncated-download': '下载提前结束，文件不完整。',
        'checksum-mismatch': '文件校验值与固定版本不符，已拒绝使用。',
        'declared-size-mismatch': '文件大小与固定版本不符，已拒绝使用。',
        'host-disk-full': '本机磁盘空间不足。',
      };
      if (own(products, job.failed_product)) region.append(el('span', 'build-job-failure', `失败项目：${products[job.failed_product]}`));
      region.append(el('span', 'build-job-failure', `原因：${own(causes, job.failure_code) ? causes[job.failure_code] : '未能识别具体原因，请按下方代码排查。'}`));
      region.append(el('span', 'build-job-failure', `代码：${typeof job.failure_code === 'string' && job.failure_code ? job.failure_code : '未记录'}`));
    }
    if (job.mode === 'preinstall' && (job.materials_source === 'reused' || job.materials_source === 'downloaded')) {
      region.append(el('span', '', job.materials_source === 'reused' ? '应用材料：复用本机已校验的缓存（本次已重新完整校验）' : '应用材料：本次重新下载'));
    }
    if (job.mode === 'preinstall' && job.phase === 'awaiting_vpn_configuration') {
      region.append(el('span', '', '尚未配置客机网络；VM 尚未发布或启动。完成此任务前不能开始其他 VM 操作。'));
      if (waitingVpnJob()) region.append(button('继续配置 VPN', 'text-button', () => openWaitingVpnConfiguration(job.id, job.name),
        !connected || preinstallBusy || !preinstallUI, 'continue-preinstall-vpn'));
    } else if (job.mode === 'preinstall' && !materialFailure) region.append(el('span', '', '发布不代表 VPN 已连通。首次设置、安装应用、导入节点、服务授权和账号登录都需要你在客机里亲自完成。'));
    if (job.mode === 'preinstall' && job.phase === 'failed' && !materialFailure) {
      // Fixed codes only; the backend never forwards native output, paths or node data.
      const reasons = {
        'installer-copy-failed': '把应用复制到首次设置文件夹失败（例如本机磁盘空间不足）。',
        'installer-copy-mismatch': '复制后的应用与已核验的原件不一致，已停止。',
        'installer-quarantine-mismatch': '复制后的应用缺少下载来源标记，已停止。',
        'runtime-preparation-failed': '准备受保护启动环境失败。',
        'internal-error': '内部检查出现意外错误；已保留现场。',
      };
      const stepKey = job.failed_step || job.failed_phase;
      const stepLabel = job.failed_step ? '' : labels[job.failed_phase] || '';
      region.append(el('span', 'build-job-failure', `失败步骤：${stepKey ? (stepLabel ? `${stepLabel}（${stepKey}）` : stepKey) : '未记录'}`));
      const reasonCode = job.failure_reason || job.failure_code || '';
      region.append(el('span', 'build-job-failure', `原因：${own(reasons, reasonCode) ? reasons[reasonCode] : '未归类，请按下方代码排查；不会自动重试。'}`));
      region.append(el('span', 'build-job-failure', `代码：${[job.failure_code, job.failure_reason].filter(Boolean).join(' / ') || '未记录'}`));
      if (job.recovery_required === true && job.published !== true) {
        region.append(button('归档此失败任务（保留暂存盘）', 'text-button', () => openArchiveJob(job), !connected));
      }
    }
    if (job.mode === 'preinstall' && job.phase === 'interrupted' && job.published === false && job.interrupted_download_archivable === true) {
      region.append(button('归档已中断的下载', 'text-button', () => openArchiveJob(job), !connected));
    }
    if (typeof job.progress === 'number') {
      const progress = el('progress'); progress.max = 1; progress.value = job.progress;
      progress.setAttribute('aria-label', '当前阶段进度');
      region.append(progress, el('span', '', `${Math.round(job.progress * 100)}%`));
    }
    if (job.phase === 'awaiting_user_setup' || (job.mode === 'preinstall' && job.published === true)) region.append(button('选择新 VM', 'text-button', () => selectVM(job.name)));
  }

  function openBuild(source = null, offline = false) {
    if (!connected || buildActive() || (!offline && !source) || (offline && (source || !state?.capabilities?.offline_validate))) return;
    buildContext = { source, offline };
    buildBusy = false;
    $('build-form').reset();
    setSetupProfile('build');
    $('build-title').textContent = offline ? '仅安装 VM（暂存）' : `彻底重建 ${source}`;
    $('build-description').textContent = offline ? '只将 macOS 恢复到全新的暂存盘。不预装软件、不复制宿主节点，也不会出现在可启动的 VM 列表中。' : '不克隆旧磁盘，不继承旧账号、缓存或凭证。旧 VM 必须先关机或暂停；此向导不会强制停止。';
    $('build-name').value = '';
    $('build-cpu').value = '2'; $('build-memory').value = '4'; $('build-disk').value = '50';
    $('build-cpu').max = String(state.host?.cpu_count || 2);
    $('build-memory').max = String(state.host?.memory_gib || 4);
    $('build-keep-name').hidden = !source;
    $('build-erase-warning').hidden = !source;
    $('build-offline-notice').hidden = !offline;
    $('build-legacy-setup').hidden = offline;
    if (offline) $('build-image-mode').value = 'local';
    $('build-image-local').hidden = !offline;
    $('build-image-mode').disabled = offline;
    $('build-error').hidden = true;
    $('build-submit').textContent = offline ? '安装到暂存盘' : '确认删除旧环境并重建';
    $('build-submit').className = source ? 'button button-danger' : 'button button-primary';
    if (source && vmById(source)?.state === 'running') showError('build-error', '这台 VM 正在运行。请先退出此向导，正常关机或暂停，再重建。');
    updateBuildForm();
    $('build-dialog').showModal();
    $('build-name').focus();
  }

  function updateBuildForm() {
    const source = buildContext?.source;
    const offline = buildContext?.offline === true;
    if (offline) $('build-image-mode').value = 'local';
    $('build-image-mode').disabled = buildBusy || offline;
    $('build-image-local').hidden = $('build-image-mode').value !== 'local';
    const disk = $('build-disk');
    const validDisk = /^\d+$/.test(disk.value) && disk.checkValidity();
    $('build-disk-error').hidden = validDisk;
    disk.setAttribute('aria-invalid', String(!validDisk));
    const resources = validDisk && ['build-cpu', 'build-memory'].every((id) => $(id).checkValidity() && Number.isInteger(Number($(id).value)));
    const name = $('build-name').value;
    const validName = name.length > 0 && name.length <= 64 && name.trim() === name && name.normalize('NFC') === name && /^[\p{L}\p{N} _-]+$/u.test(name) && !/^[.-]/.test(name);
    const valid = resources && validName && (offline ? $('build-offline-ack').checked : $('build-setup-ack').checked) &&
      ($('build-image-mode').value !== 'local' || $('build-ipsw').value.startsWith('/')) &&
      (!source || ($('build-erase-ack').checked && ['stopped', 'suspended'].includes(vmById(source)?.state)));
    $('build-submit').disabled = buildBusy || !connected || buildActive() || !valid;
  }

  async function submitBuild(event) {
    event.preventDefault();
    updateBuildForm();
    if (buildBusy || $('build-submit').disabled || !buildContext) return;
    const source = buildContext.source;
    const offline = buildContext.offline === true;
    if (!offline && !source) return;
    const body = { mode: offline ? 'offline_validate' : 'rebuild', name: $('build-name').value,
      cpu: Number($('build-cpu').value), memory_gib: Number($('build-memory').value), disk_gib: Number($('build-disk').value),
      ipsw: $('build-image-mode').value === 'local' ? $('build-ipsw').value : 'latest' };
    if (offline) body.acknowledge_offline = $('build-offline-ack').checked;
    else {
      try { body.setup_profile = readSetupProfile('build'); }
      catch (error) { showError('build-error', error.message); return; }
      body.acknowledge_setup = $('build-setup-ack').checked;
    }
    if (source) Object.assign(body, { source_vm: source, confirm_name: source, acknowledge_erase: $('build-erase-ack').checked });
    buildBusy = true;
    $('build-dialog').querySelectorAll('input,select,button').forEach((item) => { item.disabled = true; });
    $('build-error').hidden = true;
    try {
      const result = await api('/api/build', { method: 'POST', body, timeout: 30000 });
      toast(result.message);
      $('build-dialog').close();
      await refresh(true);
    } catch (error) { showError('build-error', error.message); }
    finally {
      buildBusy = false;
      $('build-dialog').querySelectorAll('input,select,button').forEach((item) => { item.disabled = false; });
      updateBuildForm();
    }
  }

  mountSetupProfile('build');
  mountSetupProfile('initialize');
  window.addEventListener('gold-initialization-status', (event) => {
    const d = event.detail;
    if (!d || typeof d.vm !== 'string' || typeof d.phase !== 'string' || typeof d.code !== 'string') return;
    const pane = $('initialization-job');
    pane.hidden = false;
    const labels = { starting: '准备中', waiting: '等待 VM 前台', running: '前端自动化中', finished: '已停止', stopped: '结果' };
    const messages = { screen_recording_permission_required: '管理器当前进程的屏幕录制权限未生效，请按原生自检提示授权并重开 App。', accessibility_permission_required: '管理器当前进程的辅助功能权限未生效。', both_permissions_required: '管理器当前进程的两项权限均未生效；未打开密码框，也未操作客机。', native_secure_form_opened: '本机安全输入框已打开。只在原生框输入，不把账号密码发给模型。', desktop_ready_requires_profile_apply: '已到桌面，时区和最终配置仍需应用／验收，不能算全部完成。', existing_login_or_lock_screen: '检测到已有账户登录／锁屏，不会尝试密码。请使用恢复入口，或在确认后重建。', unsupported_language: '当前自动引擎仅支持英语美国，其他语言模板尚未自动验收。', checkbox_state_requires_user: '无法确认隐私开关状态，已停止，没有盲目切换。', timezone_requires_manual_selection: '系统出现单独时区页面，自动化已停止；未声称时区已配置。', bring_exact_vm_window_frontmost: '请保持这台 VM 完整位于单一屏幕且在前台，勿切换窗口或操作键鼠。' };
    pane.replaceChildren(el('strong', '', `自动初始化 ${d.vm} · ${labels[d.phase] || d.phase}`), el('span', '', messages[d.code] || d.code));
  });
  mountGrowth();
  $('delete-form').addEventListener('input', updateDeleteForm);
  $('delete-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    updateDeleteForm();
    if ($('delete-submit').disabled || !deleteContext) return;
    const id = deleteContext.id;
    deleteBusy = true;
    busyVMs.add(id);
    $('delete-dialog').querySelectorAll('input,button').forEach((item) => { item.disabled = true; });
    $('delete-error').hidden = true;
    render();
    try {
      // Clicking the red button in this dialog is the confirmation; the request names this exact VM.
      const result = await api(`/api/vms/${encodeURIComponent(id)}/delete`, { method: 'POST', body: { confirm_name: id, acknowledge_erase: true } });
      toast(result.message || '删除请求已发送，请等待本机服务确认。');
      $('delete-dialog').close();
      await refresh();
    } catch (error) { showError('delete-error', error.message); }
    finally {
      deleteBusy = false;
      busyVMs.delete(id);
      $('delete-dialog').querySelectorAll('input,button').forEach((item) => { item.disabled = false; });
      updateDeleteForm();
      render();
    }
  });
  $('delete-dialog').addEventListener('cancel', (event) => { if (deleteBusy) event.preventDefault(); });
  $('delete-dialog').addEventListener('close', () => { deleteContext = null; });
  $('initialize-dialog').addEventListener('close', () => { initializeContext = null; });
  $('initialize-form').addEventListener('submit', (event) => {
    event.preventDefault();
    const vm = vmById(initializeContext?.id);
    if (!vm || locked(vm) || !vm.setup_required || vm.state !== 'running' || vm.recovery_mode) { showError('initialize-error', 'VM 状态已变化。仅支持正在普通运行且仍待初始设置的 VM，请刷新状态。'); return; }
    const bridge = nativeInitializationBridge();
    if (!bridge) { showError('initialize-error', '请在原生 App 使用；浏览器不能执行安全初始化。'); return; }
    try {
      bridge.postMessage({ vm_id: vm.id, setup_profile: readSetupProfile('initialize') });
      $('initialize-dialog').close();
      toast('已请求原生 App 打开安全凭据表单；尚未确认初始化完成。');
    } catch (_) { showError('initialize-error', '无法打开原生初始化，请确认在原生 App 中使用。'); }
  });

  if (window.GoldPreinstall) preinstallUI = window.GoldPreinstall.mount({
    document, api,
    getContext: () => ({ connected, active: buildActive(), waitingJob: waitingVpnJob(), names: VM_IDS, host: state?.host || {},
      // VMs that keep the node configuration they were built with (only the names leave here).
      nodeSources: (state?.vms || []).filter((vm) => vm.preinstalled?.installers_share === true).map((vm) => vm.id) }),
    onBusy: (value) => { preinstallBusy = value; render(true); },
    onQueued: async (job, { resumed, deferred }) => {
      // Drain a poll that may predate the POST, especially a waiting snapshot
      // with the very same job ID. preinstallBusy keeps actions locked meanwhile.
      if (pollFlight) await pollFlight;
      if (state) state.build_job = { ...job, mode: 'preinstall' };
      render(true);
      toast(resumed ? '继续配置请求已接收；不会自动开机或连接 VPN。' :
        deferred ? '预装请求已接收；系统与应用装好后会等待你配置 VPN，不会自动开机。' :
        '预装请求已接收；不会自动首次开机，VPN 与桌面功能仍待真人验收。');
      await refresh(true);
    },
  });
  $('preinstall-new').addEventListener('click', () => { $('create-advanced').open = false; preinstallUI?.open(); });
  $('new-vm').addEventListener('click', () => { $('create-advanced').open = false; openBuild(null, true); });
  $('build-form').addEventListener('submit', submitBuild);
  $('build-form').addEventListener('input', updateBuildForm);
  $('build-image-mode').addEventListener('change', updateBuildForm);
  $('build-keep-name').addEventListener('click', () => { $('build-name').value = buildContext?.source || ''; updateBuildForm(); });
  $('build-dialog').addEventListener('cancel', (event) => { if (buildBusy) event.preventDefault(); });
  $('pick-ipsw').addEventListener('click', async () => {
    if (buildBusy || nativePickerBusy) return;
    nativePickerBusy = true; buildBusy = true; updateBuildForm(); $('pick-ipsw').disabled = true;
    try {
      const result = await api('/api/pick-ipsw', { method: 'POST', body: {}, timeout: 200000 });
      if (!result.cancelled && $('build-dialog').open) $('build-ipsw').value = result.path;
    } catch (error) { showError('build-error', error.message); }
    finally { nativePickerBusy = false; buildBusy = false; $('pick-ipsw').disabled = false; updateBuildForm(); }
  });

  function openToken() { $('token-input').value = ''; $('token-dialog').showModal(); }

  $('refresh').addEventListener('click', () => refresh(true));
  $('connection-settings').addEventListener('click', openToken);
  $('pick-directory').addEventListener('click', pickDirectory);
  $('share-form').addEventListener('submit', submitShare);
  $('confirm-form').addEventListener('submit', submitConfirm);
  ['share-name', 'share-mode', 'share-enabled', 'write-ack'].forEach((id) => $(id).addEventListener('input', updateShareForm));
  $('share-path').addEventListener('input', () => { $('write-ack').checked = false; updateShareForm(); });
  $('token-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    token = $('token-input').value.trim();
    if (!token) return;
    try { sessionStorage.setItem(TOKEN_KEY, token); } catch (_) { toast('浏览器未允许会话存储，刷新后需要重新输入令牌。', true); }
    $('token-input').value = '';
    $('token-dialog').close();
    await refresh(true);
  });
  document.querySelectorAll('.dialog-close').forEach((item) => item.addEventListener('click', () => item.closest('dialog').close()));
  $('share-dialog').addEventListener('cancel', (event) => { if (dialogBusy) event.preventDefault(); });
  $('confirm-dialog').addEventListener('cancel', (event) => { if (confirmBusy) event.preventDefault(); });
  $('share-dialog').addEventListener('close', () => { shareContext = null; });
  $('confirm-dialog').addEventListener('close', () => { confirmContext = null; });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  render();
  refresh();
  setInterval(() => { if (!document.hidden) refresh(); }, 3000);
})();
