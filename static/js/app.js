const API = '/api';
const TOKEN_KEY = 'wg_token';
let currentTab = 'peers';
let previousPeerIds = new Set();
let refreshTimer = null;
let expandedPeers = new Set();
let peerSearch = '';
let expandedInputs = {};
let activeElementId = null;
let activeElementCursorStart = null;
let activeElementCursorEnd = null;
let _keeneticPeerId = null;
let routerCheckTimer = null;
const THEME_KEY = 'ncmanager_theme';

function getSystemTheme() {
	return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function getSavedTheme() {
	try {
		const saved = localStorage.getItem(THEME_KEY);
		if (saved === 'light' || saved === 'dark') return saved;
	} catch (e) {}
	return null;
}

function applyTheme(mode) {
	const root = document.documentElement;
	if (mode === 'light') {
		root.classList.add('light');
		root.setAttribute('data-theme', 'light');
		root.style.colorScheme = 'light';
	} else {
		root.classList.remove('light');
		root.setAttribute('data-theme', 'dark');
		root.style.colorScheme = 'dark';
	}
}

function toggleTheme() {
	const current = document.documentElement.classList.contains('light') ? 'light' : 'dark';
	const next = current === 'dark' ? 'light' : 'dark';
	applyTheme(next);
	try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
}

function initTheme() {
	const saved = getSavedTheme();
	const mode = saved || getSystemTheme();
	applyTheme(mode);
}

const AMNEZIA_SPARKLINE_CACHE = new Map();

async function loadAmneziaSparkline(name) {
	try {
		const res = await xhr('GET', '/amnezia/interface/' + encodeURIComponent(name) + '/stats?period=5m');
		if (!res.ok) return;
		const data = await res.json();
		if (!data || !data.points || data.points.length < 2) return;
		const rx = [];
		const tx = [];
		for (const pt of data.points) {
			rx.push(pt.rx || 0);
			tx.push(pt.tx || 0);
		}
		AMNEZIA_SPARKLINE_CACHE.set(name, { rx, tx, ts: Date.now() });
		const card = document.querySelector('.awg-card[data-name="' + name.replace(/"/g, '\\"') + '"]');
		if (card) {
			const sparkEl = card.querySelector('.awg-card-chart svg');
			const rxEl = card.querySelector('.awg-traffic-rate.rx');
			const txEl = card.querySelector('.awg-traffic-rate.tx');
			const downsampledRx = downsampleMaxAmnezia(rx, 60);
			const downsampledTx = downsampleMaxAmnezia(tx, 60);
			const newSparkline = buildAmneziaSparkline(downsampledRx, downsampledTx);
			if (sparkEl) sparkEl.outerHTML = newSparkline;
			const curRx = downsampledRx.length ? downsampledRx[downsampledRx.length - 1] : 0;
			const curTx = downsampledTx.length ? downsampledTx[downsampledTx.length - 1] : 0;
			if (rxEl) rxEl.textContent = '↓ ' + formatRate(curRx);
			if (txEl) txEl.textContent = '↑ ' + formatRate(curTx);
		}
	} catch (e) {
		console.error('loadAmneziaSparkline failed:', e);
	}
}

function getAmneziaSparklineRates(name) {
	const entry = AMNEZIA_SPARKLINE_CACHE.get(name);
	if (!entry) return { rx: [], tx: [] };
	return {
		rx: downsampleMaxAmnezia(entry.rx, 60),
		tx: downsampleMaxAmnezia(entry.tx, 60)
	};
}

function downsampleMaxAmnezia(src, target) {
	if (!src || src.length <= target) return src || [];
	const bucket = src.length / target;
	const out = new Array(target);
	for (let i = 0; i < target; i++) {
		const start = Math.floor(i * bucket);
		const end = Math.min(src.length, Math.floor((i + 1) * bucket));
		let m = src[start] || 0;
		for (let j = start + 1; j < end; j++) {
			if (src[j] > m) m = src[j];
		}
		out[i] = m;
	}
	return out;
}

async function loadAmneziaHistory(name, period) {
	try {
		const res = await xhr('GET', '/amnezia/interface/' + encodeURIComponent(name) + '/stats?period=' + encodeURIComponent(period || '1h'));
		if (res.ok) {
			const data = await res.json();
			if (!data || !data.points) return;
			AMNEZIA_SPARKLINE_CACHE.set(name, {
				rx: data.points.map(pt => pt.rx || 0),
				tx: data.points.map(pt => pt.tx || 0),
				ts: Date.now()
			});
		}
	} catch (e) {
		console.error('loadAmneziaHistory failed:', e);
	}
}

function getToken() {
	return sessionStorage.getItem(TOKEN_KEY) || '';
}

function setToken(token) {
	if (token) {
		sessionStorage.setItem(TOKEN_KEY, token);
	} else {
		sessionStorage.removeItem(TOKEN_KEY);
	}
}

function xhr(method, path, body) {
	return new Promise((resolve, reject) => {
		const x = new XMLHttpRequest();
		x.open(method, API + path, true);
		x.setRequestHeader('Content-Type', 'application/json');
		const token = getToken();
		if (token) {
			x.setRequestHeader('Authorization', 'Bearer ' + token);
		}
		x.onreadystatechange = function() {
			if (x.readyState !== 4) return;
			if (x.status === 401) {
				setToken('');
				showLogin();
				reject(new Error('Unauthorized'));
				return;
			}
			resolve({
				ok: x.status >= 200 && x.status < 300,
				status: x.status,
				json: () => { try { return JSON.parse(x.responseText); } catch(e) { return {}; } },
				text: () => x.responseText
			});
		};
		x.onerror = () => reject(new Error('Network error'));
		x.send(body ? JSON.stringify(body) : null);
	});
}

function showLogin() {
	document.getElementById('loginOverlay').classList.remove('hidden');
}

function hideLogin() {
	document.getElementById('loginOverlay').classList.add('hidden');
}

async function login() {
	try {
		const pw = document.getElementById('password').value;
		const res = await xhr('POST', '/login', { password: pw });
		if (res.ok) {
			const data = res.json();
			if (data && data.token) {
				setToken(data.token);
			}
			if (data && data.requirePasswordChange === "true") {
				document.getElementById('loginForm').style.display = 'none';
				const cpForm = document.getElementById('changePasswordForm');
				if (cpForm) cpForm.style.display = '';
				document.getElementById('newPassword').focus();
			} else {
				await init();
			}
		} else {
			alert('Неверный пароль');
		}
	} catch (e) {
		alert('Ошибка: ' + e.message);
	}
}

async function changePassword() {
	const pw = document.getElementById('newPassword').value;
	if (!pw) return alert('Введите новый пароль');
	try {
		const res = await xhr('POST', '/auth/change-password', { newPassword: pw });
		if (res.ok) {
			setToken('');
			showLogin();
			document.getElementById('changePasswordForm').style.display = 'none';
			document.getElementById('loginForm').style.display = '';
			document.getElementById('password').value = '';
			document.getElementById('newPassword').value = '';
		} else {
			alert('Ошибка смены пароля: ' + res.text());
		}
	} catch (e) {
		alert('Ошибка: ' + e.message);
	}
}

async function logout() {
	stopAutoRefresh();
	stopRouterCheck();
	setToken('');
	await xhr('POST', '/logout');
	showLogin();
}

function switchTab(name, btn) {
	currentTab = name;
	document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('nav-link--active'));
	document.querySelectorAll('.mobile-nav-link').forEach(link => link.classList.remove('nav-link--active'));
	if (btn) btn.classList.add('nav-link--active');
	document.querySelectorAll('[id^="tab-"]').forEach(el => el.style.display = 'none');
	const target = document.getElementById('tab-' + name);
	if (target) target.style.display = '';
	if (name === 'logs') loadLogs();
	if (name === 'dns') loadDnsRoutes();
  if (name === 'waniface') loadAmneziaInterfaces();
  if (name !== 'waniface') cancelAmneziaPingRefresh();
	try { localStorage.setItem('ncmanager_tab', name); } catch (e) {}
	closeMobileMenu();
}

function toggleMobileMenu() {
	document.getElementById('mobileNav').classList.toggle('open');
}
function closeMobileMenu() {
	const nav = document.getElementById('mobileNav');
	if (nav) nav.classList.remove('open');
}

async function loadConfig() {
	try {
		const data = await (await xhr('GET', '/config')).json();
		return data;
	} catch (e) {
		return {};
	}
}

async function loadPeers() {
	return (await xhr('GET', '/peers')).json();
}

async function loadStatus() {
	return (await xhr('GET', '/status')).json();
}

function onPeerSearchChange(value) {
	peerSearch = value.trim();
	loadPeers().then(renderPeers);
}

function editCreatedAt(peerId, cell) {
	const current = cell.textContent.trim();
	const parts = current.split('.');
	const input = document.createElement('input');
	input.type = 'date';
	input.value = parts.length === 3 ? `${parts[2]}-${parts[1]}-${parts[0]}` : '';
	input.style.cssText = 'background:var(--color-bg-primary);color:var(--color-text-primary);border:1px solid var(--color-accent);border-radius:var(--radius-sm);padding:4px 6px;font-family:var(--font-sans);font-size:0.85rem;width:100%;box-sizing:border-box';
	cell.textContent = '';
	cell.appendChild(input);
	input.focus();
	input.select();

	function save() {
		if (!input.value) {
			loadPeers();
			return;
		}
		const iso = input.value + 'T00:00:00Z';
		xhr('POST', '/peers/update', { id: peerId, createdAt: iso })
			.then(() => loadPeers())
			.catch(() => loadPeers());
	}

	input.addEventListener('blur', save);
	input.addEventListener('keydown', function(e) {
		if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
		if (e.key === 'Escape') { loadPeers(); }
	});
}

function renderPeers(peers) {
	const query = peerSearch.trim().toLowerCase();
	const filtered = query ? peers.filter(p => (p.name || '').toLowerCase().includes(query)) : peers;
	const tbody = document.getElementById('peersTable');
	if (!filtered.length) {
		tbody.innerHTML = query ? '<p style="color:#64748b;padding:12px">Нет совпадений</p>' : '<p style="color:#64748b;padding:12px">Нет пиров</p>';
		return;
	}
	let html = '<table><thead><tr><th></th><th>Имя</th><th>IP</th><th>Создан</th><th>Handshake</th><th>Endpoint</th><th>Трафик</th><th>Оплата</th><th>Действия</th><th></th></tr></thead><tbody>';
	for (const p of peers) {
		const hs = humanTimeAgo(p.lastHandshake);
		const age = getPeerAge(p.lastHandshake);
		const status = getPeerStatus(age);
		const rx = formatBytes(p.transferRx || 0);
		const tx = formatBytes(p.transferTx || 0);
		const created = new Date(p.createdAt).toLocaleDateString('ru-RU');
		const endpoint = p.endpoint && p.endpoint !== '::' && p.endpoint !== '(none)' ? p.endpoint : '—';
		const rowClass = status.class === 'offline' ? 'peer-row-offline' : '';
		const isExpanded = expandedPeers.has(p.id);
		const arrow = isExpanded ? '▼' : '▶';
		html += `<tr class="${rowClass}" data-peer-id="${p.id}">
			<td style="width:20px;padding:8px 4px"><span class="led led-gray" id="router-led-${p.id}" title="Проверка доступности роутера..."></span></td>
			<td><span class="peer-name-toggle" onclick="togglePeerDetails('${p.id}', event)" style="cursor:pointer;color:#38bdf8">${escapeHtml(p.name)}</span></td>
			<td><code>${escapeHtml(p.allowedIPs)}</code></td>
			<td><span class="created-at-editable" ondblclick="editCreatedAt('${p.id}', this)" title="Двойной клик для редактирования">${created}</span></td>
			<td><span class="peer-age ${status.class}" data-field="handshake" title="${p.lastHandshake && new Date(p.lastHandshake).getTime() >= MIN_REASONABLE_DATE ? new Date(p.lastHandshake).toLocaleString('ru-RU') : 'никогда'}">${status.text} · ${hs}</span></td>
			<td><code>${escapeHtml(endpoint)}</code></td>
			<td data-field="traffic"><span title="↑ ${tx}">↑ ${tx}</span> / <span title="↓ ${rx}">↓ ${rx}</span></td>
			<td><span class="paid-indicator-row ${p.paid ? 'paid-indicator-row--on' : 'paid-indicator-row--off'}" title="${p.paid ? 'Оплачено' : 'Не оплачено'}">${p.paid ? '$' : '$'}</span></td>
			<td class="peer-actions">
				<button class="btn-qr" onclick="showQR('${p.id}','${escapeHtml(p.name)}')">QR</button>
				<button class="btn-qr" onclick="showText('${p.id}','${escapeHtml(p.name)}')" title="Конфиг пира" style="font-size:0.75rem;font-weight:700;padding:4px 6px;min-width:38px">TXT</button>
				<button class="btn-dl" onclick="downloadConf('${p.id}')">⬇</button>
  			<button class="btn-qr" onclick="configureRouter('${p.id}')" title="Настроить VPN на роутере Keenetic" style="font-size:0.75rem;font-weight:700;padding:4px 6px;min-width:38px">VPN</button>
  			<button class="btn-qr" onclick="configureDnsRouter('${p.id}')" title="Настроить DNS на роутере Keenetic" style="font-size:0.75rem;font-weight:700;padding:4px 6px;min-width:38px">DNS</button>
				<button class="btn-del" onclick="removePeer('${p.id}')">✕</button>
			</td>
			<td style="text-align:right;width:30px"><span class="peer-arrow" onclick="togglePeerDetails('${p.id}', event)" style="cursor:pointer;color:#64748b">${arrow}</span></td>
		</tr>
		<tr id="details-${p.id}" class="peer-details" style="display:${isExpanded ? '' : 'none'}">
			<td colspan="10">
				<div class="peer-details-content">
					<h4>Настройки роутера для ${escapeHtml(p.name)}</h4>
					<div class="grid-form">
						<label>Домен<input id="rd-${p.id}" value="${escapeHtml(p.routerDomain || '')}" placeholder="router.local"></label>
						<label>Логин<input id="rl-${p.id}" value="${escapeHtml(p.routerLogin || '')}" placeholder="admin"></label>
 <label>Пароль<span class="pwd-wrap"><input type='password' id='rp-${p.id}' value='${escapeHtml(p.routerPassword || '')}' placeholder='••••••'><button type='button' class='pwd-toggle' onclick="togglePwd('rp-${p.id}', this)" title="Показать/скрыть">👁</button></span></label>
 						<label style="display:inline-flex;align-items:center;gap:6px;margin-left:12px;cursor:pointer"><input type='checkbox' id='rpaid-${p.id}' class="paid-input" ${p.paid ? 'checked' : ''} onchange="togglePeerPaid('${p.id}', this.checked)" style="position:absolute;opacity:0;width:0;height:0"><span class="paid-indicator ${p.paid ? 'paid-indicator--on' : 'paid-indicator--off'}"></span><span class="paid-label">Оплачено</span></label>
 						<p id="routerStatus-${p.id}" style="grid-column:1/-1;color:#059669;font-size:0.85rem"></p>
  						<label style="grid-column:1/-1">Описание<textarea id='rdesc-${p.id}' rows="4" style="width:100%;padding:6px;border-radius:4px;background:var(--color-bg-primary);color:var(--color-text-primary);border:1px solid var(--color-border);font-family:var(--font-sans);font-size:0.85rem;resize:vertical;min-height:100px" placeholder='Комментарий'>${escapeHtml(p.description || '')}</textarea></label>
  					</div>
  					<button id="saveRouterBtn-${p.id}" onclick="savePeerRouter('${p.id}')" class="btn-dl" style="margin-top:8px">Сохранить</button>
  					<button onclick="configureRouter('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить VPN</button>
  					<button onclick="configureDnsRouter('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить DNS</button>
  					<button onclick="configureDnsRoutes('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить DNS-маршрутизацию</button>
  					<button onclick="configureComponents('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить компоненты</button>
  				</div>
  			</td>
  		</tr>`;
	}
	html += '</tbody></table>';
	tbody.innerHTML = html;
	const countEl = document.getElementById('peerMetaCount');
	const unpaidEl = document.getElementById('peerMetaUnpaid');
	if (countEl && unpaidEl) {
		const total = peers.length;
		const unpaid = peers.filter(p => !p.paid).length;
		countEl.textContent = total + ' всего/ ';
		unpaidEl.textContent = unpaid + ' неоплачено';
		unpaidEl.classList.toggle('peer-meta-unpaid', unpaid > 0);
	}
}

function updatePeerStats(peers) {
	const tbody = document.getElementById('peersTable');
	if (!tbody) return;
	for (const p of peers) {
		const row = tbody.querySelector('tr[data-peer-id="' + p.id + '"]');
		if (!row) continue;
		const age = getPeerAge(p.lastHandshake);
		const status = getPeerStatus(age);
		const rx = formatBytes(p.transferRx || 0);
		const tx = formatBytes(p.transferTx || 0);
		const hs = humanTimeAgo(p.lastHandshake);
		row.className = status.class === 'offline' ? 'peer-row-offline' : '';
		const handshakeEl = row.querySelector('[data-field="handshake"]');
		if (handshakeEl) {
			handshakeEl.className = 'peer-age ' + status.class;
			handshakeEl.title = p.lastHandshake && new Date(p.lastHandshake).getTime() >= MIN_REASONABLE_DATE ? new Date(p.lastHandshake).toLocaleString('ru-RU') : 'никогда';
			handshakeEl.innerHTML = status.text + ' · ' + hs;
		}
		const trafficEl = row.querySelector('[data-field="traffic"]');
		if (trafficEl) {
			trafficEl.innerHTML = '<span title="↑ ' + tx + '">↑ ' + tx + '</span> / <span title="↓ ' + rx + '">↓ ' + rx + '</span>';
		}
		const paidEl = row.querySelector('.paid-indicator-row');
		if (paidEl) {
			paidEl.className = 'paid-indicator-row ' + (p.paid ? 'paid-indicator-row--on' : 'paid-indicator-row--off');
			paidEl.title = p.paid ? 'Оплачено' : 'Не оплачено';
		}
	}
	const countEl = document.getElementById('peerMetaCount');
	const unpaidEl = document.getElementById('peerMetaUnpaid');
	if (countEl && unpaidEl) {
		const total = peers.length;
		const unpaid = peers.filter(p => !p.paid).length;
		countEl.textContent = total + ' всего/ ';
		unpaidEl.textContent = unpaid + ' неоплачено';
		unpaidEl.classList.toggle('peer-meta-unpaid', unpaid > 0);
	}
}

function updateRouterLed(peerId, routerDomain) {
	const led = document.getElementById('router-led-' + peerId);
	if (!led) return;
	if (!routerDomain) {
		led.className = 'led led-gray';
		led.title = 'Домен роутера не настроен';
		return;
	}
	xhr('GET', '/peers/router-check/' + encodeURIComponent(peerId))
		.then(res => {
			if (res.ok) {
				const data = res.json();
				if (data.available) {
					led.className = 'led led-green';
					led.title = data.model ? ('Модель: ' + data.model + ' | Версия: ' + data.version) : 'Роутер доступен';
				} else {
					led.className = 'led led-gray';
					led.title = 'Роутер недоступен';
				}
			} else {
				led.className = 'led led-gray';
				led.title = 'Проверка невозможна';
			}
		})
		.catch(() => {
			led.className = 'led led-gray';
			led.title = 'Ошибка проверки';
		});
}

function checkAllRouters() {
	const ledEls = document.querySelectorAll('.led');
	for (const led of ledEls) {
		if (!led.id || !led.id.startsWith('router-led-')) continue;
		const peerId = led.id.replace('router-led-', '');
		xhr('GET', '/peers/router-check/' + encodeURIComponent(peerId))
			.then(res => {
				if (res.ok) {
					const data = res.json();
					if (data.available) {
						led.className = 'led led-green';
						led.title = data.model ? ('Модель: ' + data.model + ' | Версия: ' + data.version) : 'Роутер доступен';
					} else {
						led.className = 'led led-gray';
						led.title = 'Роутер недоступен';
					}
				} else {
					led.className = 'led led-gray';
					led.title = 'Проверка невозможна';
				}
			})
			.catch(() => {
				led.className = 'led led-gray';
				led.title = 'Ошибка проверки';
			});
	}
}

function togglePwd(inputId, btn) {
	const input = document.getElementById(inputId);
	if (!input) return;
	if (input.type === 'password') {
		input.type = 'text';
		btn.textContent = '🙈';
	} else {
		input.type = 'password';
		btn.textContent = '👁';
	}
}

function togglePeerDetails(id, e) {
	if (e) e.preventDefault();
	const row = document.getElementById('details-' + id);
	if (row) {
		const isHidden = row.style.display === 'none';
		if (isHidden) {
			expandedPeers.clear();
			expandedPeers.add(id);
		} else {
			expandedPeers.delete(id);
		}
		document.querySelectorAll('.peer-details').forEach(r => {
			const rid = r.id.replace('details-', '');
			r.style.display = expandedPeers.has(rid) ? '' : 'none';
		});
	}
}

async function savePeerRouter(id, silent) {
	const routerDomain = document.getElementById('rd-' + id).value.trim();
	const routerLogin = document.getElementById('rl-' + id).value.trim();
	const routerPassword = document.getElementById('rp-' + id).value;
	const description = document.getElementById('rdesc-' + id).value.trim();
	const paidEl = document.getElementById('rpaid-' + id);
	const paid = paidEl ? paidEl.checked : false;
	const btn = document.getElementById('saveRouterBtn-' + id);
	const oldText = btn ? btn.textContent : 'Сохранить';
	try {
		const res = await xhr('POST', '/peers/update', {
			id: id,
			routerDomain: routerDomain,
			routerLogin: routerLogin,
			routerPassword: routerPassword,
			description: description,
			paid: paid,
		});
		if (!silent && res.ok) {
			if (btn) {
				btn.textContent = 'Сохранено';
				btn.classList.add('copied');
				setTimeout(() => {
					btn.textContent = oldText;
					btn.classList.remove('copied');
				}, 2000);
			}
			if (routerDomain && routerLogin && routerPassword) {
				fetchRouterInfo(id);
			}
		}
		return res.ok;
	} catch (e) {
		if (!silent) {
			if (btn) {
				btn.textContent = 'Ошибка';
				btn.classList.add('copy-error');
				setTimeout(() => {
					btn.textContent = oldText;
					btn.classList.remove('copy-error');
				}, 2000);
			}
		}
		return false;
	}
}

async function togglePeerPaid(id, checked) {
	const indicator = document.querySelector('label:has(#rpaid-' + id + ') .paid-indicator');
	try {
		await xhr('POST', '/peers/update', {
			id: id,
			paid: checked,
		});
		if (indicator) {
			indicator.className = 'paid-indicator ' + (checked ? 'paid-indicator--on' : 'paid-indicator--off');
		}
	} catch (e) {
		const el = document.getElementById('rpaid-' + id);
		if (el) el.checked = !checked;
		if (indicator) {
			indicator.className = 'paid-indicator ' + (!checked ? 'paid-indicator--on' : 'paid-indicator--off');
		}
		alert('Ошибка обновления статуса оплаты');
	}
}

async function fetchRouterInfo(id) {
	try {
		const res = await xhr('GET', '/peers/router-info/' + id);
		if (res.ok) {
			const info = await res.json();
			const statusEl = document.getElementById('routerStatus-' + id);
			if (statusEl) {
				statusEl.textContent = `Модель: ${info.model || '—'} | Версия: ${info.version || '—'}`;
			}
		}
	} catch (e) {}
}

const MIN_REASONABLE_DATE = new Date('2020-01-01T00:00:00Z').getTime();

function humanTimeAgo(iso) {
	if (!iso) return '—';
	const d = new Date(iso);
	if (isNaN(d.getTime()) || d.getTime() < MIN_REASONABLE_DATE) return '—';
	const diff = Math.floor((Date.now() - d.getTime()) / 1000);
	if (diff < 60) return `${diff} сек.`;
	if (diff < 3600) {
		const m = Math.floor(diff / 60);
		const s = diff % 60;
		return `${m} мин. ${s} сек.`;
	}
	if (diff < 86400) {
		const h = Math.floor(diff / 3600);
		const m = Math.floor((diff % 3600) / 60);
		return `${h} ч. ${m} мин.`;
	}
	const days = Math.floor(diff / 86400);
	const h = Math.floor((diff % 86400) / 3600);
	return `${days} дн. ${h} ч.`;
}

function getPeerAge(hs) {
	if (!hs) return Infinity;
	const d = new Date(hs);
	if (isNaN(d.getTime()) || d.getTime() < MIN_REASONABLE_DATE) return Infinity;
	return Date.now() - d.getTime();
}

function getPeerStatus(ageSec) {
	if (ageSec === Infinity) return { text: 'Нет', class: 'offline' };
	if (ageSec < 3 * 60 * 1000) return { text: 'Онлайн', class: 'online' };
	if (ageSec < 10 * 60 * 1000) return { text: 'Недавно', class: 'recent' };
	return { text: 'Оффлайн', class: 'offline' };
}

function formatBytes(b) {
	if (b < 1024) return b + ' B';
	const u = 1024, e = Math.floor(Math.log(b) / Math.log(u));
	return (b / Math.pow(u, e)).toFixed(1) + ' ' + 'KMGTPE'[e-1] + 'iB';
}

function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const d = domain.trim().toLowerCase();
  if (d.length === 0 || d.length > 253) return false;
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const parts = d.split('.');
  if (parts.length < 1) return false;
  return parts.every(p => p.length <= 63 && domainRegex.test(p));
}

function validateDnsRouteInput(domains, subnets) {
  const invalidDomains = domains.filter(d => !isValidDomain(d)).slice(0, 3);
  if (invalidDomains.length) {
    return 'Неверные домены: ' + invalidDomains.join(', ');
  }
  return '';
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

async function addPeer() {
	const name = document.getElementById('peerName').value.trim();
	previousPeerIds.clear();
	if (!name) return alert('Введите имя пира');
	try {
		const res = await xhr('POST', '/peers/add', { name });
		if (res.ok) {
			document.getElementById('peerName').value = '';
			refresh();
		} else {
			alert('Ошибка: ' + res.text());
		}
	} catch (e) {
		alert('Ошибка: ' + e.message);
	}
}

async function removePeer(id) {
	if (!confirm('Удалить пира?')) return;
	previousPeerIds.clear();
	try {
		const res = await xhr('POST', '/peers/remove', { id });
		if (res.ok) refresh();
	} catch (e) {
		alert('Ошибка: ' + e.message);
	}
}

async function toggleServer() {
	try {
		const status = await loadStatus();
		if (status.running) {
			await xhr('POST', '/server/stop');
		} else {
			await xhr('POST', '/server/start');
		}
		refresh();
	} catch (e) {
		alert('Ошибка: ' + e.message);
	}
}

function showQR(id, name) {
	document.getElementById('qrPeerName').textContent = name || id;
	const img = document.getElementById('qrImage');
	img.src = '';
	img.style.opacity = '0.3';
	document.getElementById('qrModal').classList.add('show');
	const token = getToken();
	fetch(API + '/peers/qrcode/?id=' + encodeURIComponent(id), {
		headers: { 'Authorization': 'Bearer ' + token }
	}).then(r => {
		if (!r.ok) throw new Error('HTTP ' + r.status);
		return r.arrayBuffer();
	}).then(buf => {
		const blob = new Blob([buf], { type: 'image/png' });
		const url = URL.createObjectURL(blob);
		img.onload = () => URL.revokeObjectURL(url);
		img.src = url;
		img.style.opacity = '1';
	}).catch(() => {
		img.style.opacity = '1';
	});
}

function closeQR() {
	document.getElementById('qrModal').classList.remove('show');
	document.getElementById('qrImage').src = '';
	document.getElementById('qrPeerName').textContent = '';
}

function showText(id, name) {
	document.getElementById('textPeerName').textContent = name || id;
	document.getElementById('textOutput').textContent = 'Загрузка...';
	document.getElementById('textModal').classList.add('show');
	xhr('GET', '/peers/config/?id=' + encodeURIComponent(id)).then(res => {
		document.getElementById('textOutput').textContent = res.text();
	}).catch(e => {
		document.getElementById('textOutput').textContent = 'Ошибка: ' + e.message;
	});
}

function closeText() {
	document.getElementById('textModal').classList.remove('show');
	document.getElementById('textOutput').textContent = '';
	document.getElementById('textPeerName').textContent = '';
}

function closeRouterModal() {
	document.getElementById('routerModal').classList.remove('show');
}

async function configureRouter(id) {
	const routerDomain = document.getElementById('rd-' + id).value.trim();
	const routerLogin = document.getElementById('rl-' + id).value.trim();
	const routerPassword = document.getElementById('rp-' + id).value;
	if (!routerDomain) return alert('Укажите домен/адрес роутера');
	if (!routerLogin) return alert('Укажите логин');
	if (!routerPassword) return alert('Укажите пароль');

	await savePeerRouter(id, true);

	_keeneticPeerId = id;

	const log = document.getElementById('routerLog');
	if (!log) return;
	log.textContent = 'Импорт конфигурации в Keenetic...\n';
	log.scrollTop = log.scrollHeight;

	const closeBtn = document.getElementById('routerCloseBtn');
	if (closeBtn) closeBtn.style.display = 'none';
	const dlBtn = document.getElementById('keeneticDownloadBtn');
	if (dlBtn) dlBtn.style.display = 'none';

	document.getElementById('routerModal').classList.add('show');
	document.getElementById('routerLog').style.display = '';

	try {
		log.textContent += '📡 Подключение к ' + routerDomain + '...\n';
		const res = await xhr('POST', '/peers/keenetic/' + encodeURIComponent(id), {});
		const data = await res.json();
		if (data.status === 'ok') {
			if (data.intersects) {
				log.textContent += '🔄 Интерфейс обновлён: ' + data.created + '\n';
			} else {
				log.textContent += '✅ Интерфейс создан: ' + data.created + '\n';
			}
			if (data.messages && data.messages.length) {
				for (const msg of data.messages) {
					log.textContent += '   ↳ ' + msg + '\n';
				}
			}
			log.textContent += '\n';
			log.textContent += 'Готово! Интерфейс активен.\n';
			log.textContent += 'Проверьте: ' + routerDomain + ' → Другие подключения → WireGuard\n';
		} else {
			log.textContent += '❌ Ошибка: ' + (data.error || 'неизвестно') + '\n';
		}
	} catch (e) {
		log.textContent += '❌ Ошибка импорта: ' + e.message + '\n';
		log.textContent += '\nВы можете скачать конфиг и импортировать вручную:\n';
		log.textContent += '1. Нажмите «Скачать конфиг»\n';
		log.textContent += '2. В Keenetic: Другие подключения → WireGuard → Загрузить из файла\n';
		const dlBtn = document.getElementById('keeneticDownloadBtn');
		if (dlBtn) dlBtn.style.display = '';
	}

 	if (closeBtn) closeBtn.style.display = '';
 }

  async function configureComponents(id) {
  	const routerDomain = document.getElementById('rd-' + id).value.trim();
  	const routerLogin = document.getElementById('rl-' + id).value.trim();
  	const routerPassword = document.getElementById('rp-' + id).value;
  	if (!routerDomain) return alert('Укажите домен/адрес роутера');
  	if (!routerLogin) return alert('Укажите логин');
  	if (!routerPassword) return alert('Укажите пароль');

  	await savePeerRouter(id, true);
  	_keeneticPeerId = id;

  	const log = document.getElementById('routerLog');
  	if (!log) return;
  	log.textContent = 'Настройка компонентов на роутере...\n';
  	log.scrollTop = log.scrollHeight;

  	const closeBtn = document.getElementById('routerCloseBtn');
  	if (closeBtn) closeBtn.style.display = 'none';
  	const dlBtn = document.getElementById('keeneticDownloadBtn');
  	if (dlBtn) dlBtn.style.display = 'none';

  	document.getElementById('routerModal').classList.add('show');
  	document.getElementById('routerLog').style.display = '';

  	try {
  		log.textContent += '📡 Подключение к ' + routerDomain + '...\n';
  		const startRes = await xhr('POST', '/components/apply', { peerId: id });
  		if (!startRes.ok) {
  			log.textContent += '❌ Ошибка запуска: ' + (await startRes.text()) + '\n';
  			if (closeBtn) closeBtn.style.display = '';
  			if (dlBtn) dlBtn.style.display = '';
  			return;
  		}

  		let pollCount = 0;
  		const poll = setInterval(async () => {
  			pollCount++;
  			try {
  				const statusRes = await xhr('GET', '/components/apply/status');
  				if (statusRes.ok) {
  					const data = await statusRes.json();
  					if (data.log) {
  						log.textContent = data.log;
  						log.scrollTop = log.scrollHeight;
  					}
  					if (data.status === 'completed' || data.status === 'failed') {
  						clearInterval(poll);
  						if (closeBtn) closeBtn.style.display = '';
  						if (dlBtn) dlBtn.style.display = '';
  					}
  				}
  			} catch (e) {
  				console.error('poll error:', e);
  			}
			if (pollCount > 600) {
  				clearInterval(poll);
  				log.textContent += '\n⏰ Таймаут ожидания\n';
  				if (closeBtn) closeBtn.style.display = '';
  				if (dlBtn) dlBtn.style.display = '';
  			}
  		}, 500);
  	} catch (e) {
  		log.textContent += '❌ Ошибка: ' + e.message + '\n';
  		if (closeBtn) closeBtn.style.display = '';
  		if (dlBtn) dlBtn.style.display = '';
  	}
  }

 async function configureDnsRouter(id) {
	const routerDomain = document.getElementById('rd-' + id).value.trim();
	const routerLogin = document.getElementById('rl-' + id).value.trim();
	const routerPassword = document.getElementById('rp-' + id).value;
	if (!routerDomain) return alert('Укажите домен/адрес роутера');
	if (!routerLogin) return alert('Укажите логин');
	if (!routerPassword) return alert('Укажите пароль');

	await savePeerRouter(id, true);

	_keeneticPeerId = id;

	const log = document.getElementById('routerLog');
	if (!log) return;
	log.textContent = 'Настройка DNS на роутере...\n';
	log.scrollTop = log.scrollHeight;

	const closeBtn = document.getElementById('routerCloseBtn');
	if (closeBtn) closeBtn.style.display = 'none';
	const dlBtn = document.getElementById('keeneticDownloadBtn');
	if (dlBtn) dlBtn.style.display = 'none';

	document.getElementById('routerModal').classList.add('show');
	document.getElementById('routerLog').style.display = '';

	try {
		log.textContent += '📡 Подключение к ' + routerDomain + '...\n';
		const res = await xhr('POST', '/peers/keenetic-dns/' + encodeURIComponent(id), {});
		const text = await res.text();
		let data;
		try { data = JSON.parse(text); } catch (e) { data = {}; }
		if (res.ok && data.status === 'ok') {
			log.textContent += '✅ DNS настроен\n';
			if (data.messages && data.messages.length) {
				for (const msg of data.messages) {
					log.textContent += '   ↳ ' + msg + '\n';
				}
			}
			log.textContent += '\nГотово!\n';
		} else {
			const errMsg = data.error || text.slice(0, 200) || 'неизвестно';
			log.textContent += '❌ Ошибка: ' + errMsg + '\n';
		}
	} catch (e) {
		log.textContent += '❌ Ошибка настройки DNS: ' + e.message + '\n';
	}

	if (closeBtn) closeBtn.style.display = '';
}

async function configureDnsRoutes(id) {
	const routerDomain = document.getElementById('rd-' + id).value.trim();
	const routerLogin = document.getElementById('rl-' + id).value.trim();
	const routerPassword = document.getElementById('rp-' + id).value;
	if (!routerDomain) return alert('Укажите домен/адрес роутера');
	if (!routerLogin) return alert('Укажите логин');
	if (!routerPassword) return alert('Укажите пароль');

	await savePeerRouter(id, true);
	_keeneticPeerId = id;

	const log = document.getElementById('routerLog');
	if (!log) return;
	log.textContent = 'Настройка DNS-маршрутизации на роутере...\n';
	log.scrollTop = log.scrollHeight;

	const closeBtn = document.getElementById('routerCloseBtn');
	if (closeBtn) closeBtn.style.display = 'none';
	const dlBtn = document.getElementById('keeneticDownloadBtn');
	if (dlBtn) dlBtn.style.display = 'none';

	document.getElementById('routerModal').classList.add('show');
	document.getElementById('routerLog').style.display = '';

	let poll = null;
	try {
		log.textContent += '📡 Подключение к ' + routerDomain + '...\n';
		const startRes = await xhr('POST', '/dns/routes/apply', { peerId: id });
		if (!startRes.ok) {
			log.textContent += '❌ Ошибка запуска: ' + (await startRes.text()) + '\n';
			if (closeBtn) closeBtn.style.display = '';
			if (dlBtn) dlBtn.style.display = '';
			return;
		}

		let pollCount = 0;
		poll = setInterval(async () => {
			pollCount++;
			try {
				const statusRes = await xhr('GET', '/dns/apply/status');
				if (statusRes.ok) {
					const data = await statusRes.json();
					if (data.log) {
						log.textContent = data.log;
						log.scrollTop = log.scrollHeight;
					}
					if (data.status === 'completed' || data.status === 'failed') {
						clearInterval(poll);
						if (closeBtn) closeBtn.style.display = '';
						if (dlBtn) dlBtn.style.display = '';
					}
				}
			} catch (e) {
				console.error('poll error:', e);
			}
			if (pollCount > 120) {
				clearInterval(poll);
				log.textContent += '\n⏰ Таймаут ожидания\n';
				if (closeBtn) closeBtn.style.display = '';
				if (dlBtn) dlBtn.style.display = '';
			}
		}, 500);
	} catch (e) {
		if (poll) clearInterval(poll);
		log.textContent += '❌ Ошибка настройки DNS-маршрутизации: ' + e.message + '\n';
		if (closeBtn) closeBtn.style.display = '';
		if (dlBtn) dlBtn.style.display = '';
	}
}

 async function fetchServerPrivKey() {
	const res = await fetch(API + '/keys/generate', {
		headers: { 'Authorization': 'Bearer ' + getToken(), 'Accept': 'application/json' },
		method: 'POST'
	});
	if (!res.ok) throw new Error('HTTP ' + res.status);
	const data = await res.json();
	return data.publicKey || '';
}

function keeneticDownload() {
	const id = _keeneticPeerId;
	if (!id) return;
	const token = getToken();
	fetch(API + '/peers/keenetic-dl/' + encodeURIComponent(id), {
		headers: { 'Authorization': 'Bearer ' + token }
	}).then(r => {
		if (!r.ok) throw new Error('HTTP ' + r.status);
		return r.blob();
	}).then(blob => {
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		const peerName = getPeerNameById(id) || 'peer';
		a.download = 'keenetic-' + peerName + '.conf';
		a.click();
		URL.revokeObjectURL(url);
	}).catch(e => {
		alert('Ошибка скачивания: ' + e.message);
	});
}

function getPeerNameById(id) {
	const peers = document.querySelectorAll('.peer-name-toggle');
	for (const el of peers) {
		if (el.getAttribute('onclick') && el.getAttribute('onclick').includes(id)) {
			return el.textContent;
		}
	}
	return null;
}

function copyText(btn) {
	const text = document.getElementById('textOutput').textContent;
	const oldText = btn ? btn.textContent : 'Скопировать';
	const target = btn || event.target;
	target.textContent = 'Копирование...';
	target.classList.remove('copied', 'copy-error');
	target.classList.add('copying');
	try {
		navigator.clipboard.writeText(text).then(() => {
			target.textContent = 'Скопировано';
			target.classList.remove('copying');
			target.classList.add('copied');
			setTimeout(() => {
				target.textContent = oldText;
				target.classList.remove('copied', 'copying', 'copy-error');
			}, 2000);
		}).catch(() => fallbackCopy(text, target, oldText));
	} catch (e) {
		fallbackCopy(text, target, oldText);
	}
}

function fallbackCopy(text, target, oldText) {
	const ta = document.createElement('textarea');
	ta.value = text;
	ta.style.position = 'fixed';
	ta.style.opacity = '0';
	document.body.appendChild(ta);
	ta.select();
	try {
		const ok = document.execCommand('copy');
		target.classList.remove('copying', 'copy-error');
		if (ok) {
			target.textContent = 'Скопировано';
			target.classList.add('copied');
		} else {
			target.textContent = 'Ошибка копирования';
			target.classList.add('copy-error');
		}
	} catch (e) {
		target.textContent = 'Ошибка копирования';
		target.classList.add('copy-error');
	}
	document.body.removeChild(ta);
	setTimeout(() => {
		target.textContent = oldText;
		target.classList.remove('copied', 'copying', 'copy-error');
	}, 2000);
}

function downloadConf(id) {
	const token = getToken();
	fetch(API + '/peers/download/?id=' + encodeURIComponent(id), {
		headers: { 'Authorization': 'Bearer ' + token }
	}).then(r => {
		if (!r.ok) throw new Error('HTTP ' + r.status);
		return r.blob();
	}).then(blob => {
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		const peerName = getPeerNameById(id) || 'peer';
		a.download = peerName + '.conf';
		a.click();
		URL.revokeObjectURL(url);
	}).catch(e => {
		alert('Ошибка скачивания: ' + e.message);
	});
}



async function loadDnsRoutes() {
  try {
    const res = await xhr('GET', '/dns/routes');
    if (res.ok) {
      const routes = await res.json();
      existingRouteNames = new Set(routes.map(r => r.name));
      renderDnsRouteList(routes);
      renderPresetCatalog();
    }
  } catch (e) {
    console.error('loadDnsRoutes error:', e);
  }
}

let DNS_PRESETS = [];
let presetsLoaded = false;
let existingRouteNames = new Set();

async function loadPresets() {
  try {
    const res = await xhr('GET', '/presets/dns-routes');
    if (res.ok) {
      DNS_PRESETS = await res.json();
      presetsLoaded = true;
      renderPresetCatalog();
    }
  } catch (e) {
    console.error('loadPresets error:', e);
  }
}

const PRESET_CATEGORIES = ['all','ai','block','cloud','developer','gaming','media','social'];
const PRESET_CAT_LABELS = {
  all:'Все', ai:'AI', block:'Блок-листы', cloud:'Облака',
  developer:'Developer', gaming:'Игры', media:'Медиа', social:'Соцсети'
};
const GROUP_PRESET_NAMES = ['Все AI сервисы', 'Все игры', 'Всё медиа'];

let activePresetCategory = 'all';

function isGroupAdded(cat, existingNames) {
  return DNS_PRESETS.some(p =>
    p.cat === cat &&
    GROUP_PRESET_NAMES.includes(p.name) &&
    existingNames.has(p.name)
  );
}

function renderPresetCatalog() {
  const filters = document.getElementById('presetFilters');
  const grid = document.getElementById('presetGrid');
  if (!filters || !grid) return;

  if (!presetsLoaded) {
    grid.innerHTML = '<p style="color:#64748b">Загрузка пресетов...</p>';
    return;
  }

  filters.innerHTML = PRESET_CATEGORIES.map(c =>
    `<button class="preset-filter ${c === activePresetCategory ? 'active' : ''}" onclick="filterPresets('${c}')">${PRESET_CAT_LABELS[c]}</button>`
  ).join('');

  const items = activePresetCategory === 'all' ? DNS_PRESETS : DNS_PRESETS.filter(p => p.cat === activePresetCategory);
  grid.innerHTML = items.map(p => {
    const catClass = 'cat-' + (p.cat || 'default');
    const isAdded = existingRouteNames.has(p.name) || isGroupAdded(p.cat, existingRouteNames);
    const parts = [];
    if (p.domains.length) parts.push(`${p.domains.length} доменов`);
    if (p.subnets && p.subnets.length) parts.push(`${p.subnets.length} CIDR`);
    const meta = parts.join(', ');
    return `<div class="preset-card ${isAdded ? 'added' : ''}" onclick="${isAdded ? '' : `addPresetRoute('${escapeHtml(p.name)}')`}">
      <div class="preset-name">${escapeHtml(p.name)} ${isAdded ? '✓' : ''}</div>
      <div class="preset-meta">
        ${meta ? `<span class="preset-count">${meta}</span>` : ''}
        <span class="preset-cat ${catClass}">${escapeHtml(p.catLabel || p.cat)}</span>
      </div>
    </div>`;
  }).join('');
}

function filterPresets(cat) {
  activePresetCategory = cat;
  renderPresetCatalog();
}

async function addPresetRoute(name) {
  if (existingRouteNames.has(name)) return;
  const preset = DNS_PRESETS.find(p => p.name === name);
  if (!preset) return;
  try {
    const res = await xhr('POST', '/dns/routes/create', {
      name: preset.name,
      domains: preset.domains,
      subnets: preset.subnets || []
    });
    if (res.ok) {
      existingRouteNames.add(name);
      loadDnsRoutes();
    } else {
      alert('Ошибка добавления: ' + (await res.text()));
    }
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

function getServiceIconHtml(name) {
  const icons = {
    'YouTube': '▶', 'Google': '🔍', 'Instagram': '📷', 'TikTok': '🎵', 'Netflix': '🎬'
  };
  const icon = icons[name] || '🌐';
  return `<div class="dns-service-icon">${icon}</div>`;
}

function getBackendLabel(route) {
  return 'NDMS';
}

function renderDnsRouteList(routes) {
  const list = document.getElementById('dnsRouteList');
  if (!list) return;
  if (!routes.length) {
    list.innerHTML = '<p style="color:#64748b">Нет маршрутов. Нажмите «+ Новый маршрут»</p>';
    return;
  }
  let html = '';
  for (const route of routes) {
    const domains = route.domains || [];
    const subnets = route.subnets || [];
    const domainCount = domains.length;
    const cidrCount = subnets.length;
    const preview = domains.slice(0, 3).join(', ') + (domainCount > 3 ? ' …' : '');
    const backendLabel = getBackendLabel(route);
    html += `<div class="dns-route-card ${route.enabled ? 'enabled' : 'disabled'}">
      <div class="dns-route-info">
        <div class="dns-route-name">
          <span class="led ${route.enabled ? 'led-green' : 'led-gray'}"></span>
          <span>${escapeHtml(route.name)}</span>
        </div>
        ${domainCount > 0 ? `<span class="card-stat">${domainCount} доменов</span>` : ''}
        ${cidrCount > 0 ? `<span class="card-stat">${cidrCount} CIDR</span>` : ''}
        ${preview ? `<div class="dns-route-domains">${escapeHtml(preview)}</div>` : ''}
      </div>
      <div class="dns-route-actions">
        <button class="dns-toggle ${route.enabled ? 'on' : ''}" onclick="toggleDnsRoute('${route.id}')" title="${route.enabled ? 'Выключить' : 'Включить'}"></button>
        <button class="dns-btn" onclick="editDnsRoute('${route.id}')" title="Изменить">✎</button>
        <button class="dns-btn" onclick="refreshDnsRoute('${route.id}')" title="Обновить">↻</button>
        <button class="dns-btn danger" onclick="deleteDnsRoute('${route.id}')" title="Удалить">✕</button>
      </div>
    </div>`;
  }
  list.innerHTML = html;
}

async function toggleDnsRoute(id) {
  try {
    const routes = await loadDnsRoutesList();
    const route = routes.find(r => r.id === id);
    if (!route) return;
    await xhr('POST', '/dns/routes/update', { id, name: route.name, domains: route.domains || [], subnets: route.subnets || [], enabled: !route.enabled });
    loadDnsRoutes();
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

async function applyDnsRoutes() {
	let poll = null;
    try {
    	const btn = event.target;
    	const oldText = btn.textContent;
    	btn.textContent = 'Применение...';
    	btn.disabled = true;
    	const log = document.getElementById('routerLog');
    	const closeBtn = document.getElementById('routerCloseBtn');
    	const dlBtn = document.getElementById('keeneticDownloadBtn');
    	if (log) {
    		log.textContent = 'Применение DNS маршрутов...\n';
    		log.scrollTop = log.scrollHeight;
    	}
    	if (closeBtn) closeBtn.style.display = 'none';
    	if (dlBtn) dlBtn.style.display = 'none';
    	document.getElementById('routerModal').classList.add('show');
    	if (log) log.style.display = '';

    	const startRes = await xhr('POST', '/dns/routes/apply');
    	if (!startRes.ok) {
    		if (log) log.textContent += '❌ Ошибка запуска: ' + (await startRes.text()) + '\n';
    		if (closeBtn) closeBtn.style.display = '';
    		if (dlBtn) dlBtn.style.display = '';
    		btn.textContent = oldText;
    		btn.disabled = false;
    		return;
    	}

    	let pollCount = 0;
    	poll = setInterval(async () => {
    		pollCount++;
    		try {
    			const statusRes = await xhr('GET', '/dns/apply/status');
    			if (statusRes.ok) {
    				const data = await statusRes.json();
    				if (log && data.log) {
    					log.textContent = data.log;
    					log.scrollTop = log.scrollHeight;
    				}
    				if (data.status === 'completed' || data.status === 'failed') {
    					clearInterval(poll);
    					if (closeBtn) closeBtn.style.display = '';
    					if (dlBtn) dlBtn.style.display = '';
    					btn.textContent = oldText;
    					btn.disabled = false;
    					if (data.status === 'failed' && log) {
    						log.textContent += '\n❌ Завершено с ошибками\n';
    					}
    				}
    			}
    		} catch (e) {
    			console.error('poll error:', e);
    		}
    		if (pollCount > 120) {
    			clearInterval(poll);
    			if (log) log.textContent += '\n⏰ Таймаут ожидания\n';
    			if (closeBtn) closeBtn.style.display = '';
    			if (dlBtn) dlBtn.style.display = '';
    			btn.textContent = oldText;
    			btn.disabled = false;
    		}
    	}, 500);
    } catch (e) {
    	if (poll) clearInterval(poll);
    	const log = document.getElementById('routerLog');
    	if (log) log.textContent += '❌ Ошибка: ' + e.message + '\n';
    	const closeBtn = document.getElementById('routerCloseBtn');
    	if (closeBtn) closeBtn.style.display = '';
    	const dlBtn2 = document.getElementById('keeneticDownloadBtn');
    	if (dlBtn2) dlBtn2.style.display = '';
    	const btn = event.target;
    	if (btn) {
    		btn.textContent = 'Настроить DNS';
    		btn.disabled = false;
    	}
    }
}

async function loadDnsRoutesList() {
  const res = await xhr('GET', '/dns/routes');
  return res.json();
}

function showAddDnsRoute() {
  showDnsRouteModal(null);
}

function editDnsRoute(id) {
  showDnsRouteModal(id);
}

async function showDnsRouteModal(id) {
  let route = null;
  if (id) {
    const routes = await loadDnsRoutesList();
    route = routes.find(r => r.id === id);
  }
  if (!route) route = { id: '', name: '', domains: [], subnets: [], enabled: true };

  const nameInput = document.getElementById('dnsRouteName');
  const domainsInput = document.getElementById('dnsRouteDomains');
  const subnetsInput = document.getElementById('dnsRouteSubnets');
  if (nameInput) nameInput.value = route.name || '';
  if (domainsInput) domainsInput.value = (route.domains || []).join('\n');
  if (subnetsInput) subnetsInput.value = (route.subnets || []).join('\n');
  
  populatePresetSelect();

  const overlay = document.getElementById('dnsRouteModalOverlay');
  if (overlay) {
    overlay.dataset.editId = id || '';
    overlay.style.display = '';
  }
}

function hideDnsRouteModal() {
  const overlay = document.getElementById('dnsRouteModalOverlay');
  if (overlay) overlay.style.display = 'none';
}

async function refreshDnsRoute(id) {
  try {
    const routes = await loadDnsRoutesList();
    const route = routes.find(r => r.id === id);
    if (!route) return;
    const res = await xhr('POST', '/dns/routes/apply', { peerId: route.tunnelId });
    if (res.ok) {
      loadDnsRoutes();
    }
  } catch (e) {
    console.error('refreshDnsRoute error:', e);
  }
}

async function saveDnsRouteModal() {
  const overlay = document.getElementById('dnsRouteModalOverlay');
  const editId = overlay ? overlay.dataset.editId : '';
  const nameInput = document.getElementById('dnsRouteName');
  const domainsInput = document.getElementById('dnsRouteDomains');
  const subnetsInput = document.getElementById('dnsRouteSubnets');
  if (!nameInput || !domainsInput || !subnetsInput) return;

  const name = nameInput.value.trim();
  if (!name) return alert('Введите название');

  const domains = domainsInput.value.split('\n').map(s => s.trim()).filter(s => s !== '');
  const subnets = subnetsInput.value.split('\n').map(s => s.trim()).filter(s => s !== '');
  
  const validationError = validateDnsRouteInput(domains, subnets);
  if (validationError) return alert('Ошибка валидации: ' + validationError);
  
  if (!domains.length && !subnets.length) return alert('Добавьте хотя бы один домен или CIDR');

  const payload = { name, domains, subnets, enabled: true };
  if (editId) payload.id = editId;

  try {
    const url = editId ? '/dns/routes/update' : '/dns/routes/create';
    const res = await xhr('POST', url, payload);
    if (res.ok) {
      hideDnsRouteModal();
      loadDnsRoutes();
    } else {
      alert('Ошибка: ' + (await res.text()));
    }
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

async function deleteDnsRoute(id) {
  if (!confirm('Удалить маршрут?')) return;
  try {
    const res = await xhr('POST', '/dns/routes/delete', { id });
    if (res.ok) loadDnsRoutes();
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

function populatePresetSelect() {
  const select = document.getElementById('dnsPresetSelect');
  if (!select) return;
  const options = DNS_PRESETS.map(p => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)} (${(p.domains?.length || 0) + (p.subnets?.length || 0)} записей)</option>`).join('');
  select.innerHTML = `<option value="">— выберите пресет —</option>${options}`;
}

function addPresetDomains() {
  const select = document.getElementById('dnsPresetSelect');
  if (!select) return;
  const preset = DNS_PRESETS.find(p => p.name === select.value);
  if (!preset) return;
  const domainsInput = document.getElementById('dnsRouteDomains');
  const subnetsInput = document.getElementById('dnsRouteSubnets');
  if (domainsInput) {
    const existing = domainsInput.value.split('\n').map(s => s.trim()).filter(s => s !== '');
    const merged = [...new Set([...existing, ...preset.domains])];
    domainsInput.value = merged.join('\n');
  }
  if (subnetsInput && preset.subnets && preset.subnets.length) {
    const existing = subnetsInput.value.split('\n').map(s => s.trim()).filter(s => s !== '');
    const merged = [...new Set([...existing, ...preset.subnets])];
    subnetsInput.value = merged.join('\n');
  }
  select.value = '';
}

async function refresh() {
	try {
		const peers = await loadPeers();
		const status = await loadStatus();
		const currentIds = new Set(peers.map(p => p.id));
		let peersChanged = currentIds.size !== previousPeerIds.size || [...currentIds].some(id => !previousPeerIds.has(id));
		if (peersChanged) {
			saveExpandedInputs();
			renderPeers(peers);
			restoreExpandedInputs();
			previousPeerIds = currentIds;
			setTimeout(checkAllRouters, 100);
		} else {
			updatePeerStats(peers);
		}
		const badge = document.getElementById('statusBadge');
		const btn = document.getElementById('btnToggle');
		if (status.running) {
			badge.textContent = 'Запущен';
			badge.className = 'status-badge up';
			if (btn) btn.checked = true;
		} else {
			badge.textContent = 'Остановлен';
			badge.className = 'status-badge down';
			if (btn) btn.checked = false;
		}
	} catch (e) {
		console.error('refresh error:', e);
	}
	if (currentTab === 'waniface') {
		loadAmneziaInterfaces();
	}
}

function saveExpandedInputs() {
	const ae = document.activeElement;
	if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA')) {
		activeElementId = ae.id;
		activeElementCursorPos = ae.selectionStart;
	}
	document.querySelectorAll('.peer-details').forEach(row => {
		const id = row.id.replace('details-', '');
		const rd = document.getElementById('rd-' + id);
		const rl = document.getElementById('rl-' + id);
		const rp = document.getElementById('rp-' + id);
		const rdesc = document.getElementById('rdesc-' + id);
		if (rd) expandedInputs[id] = { rd: rd.value, rl: rl ? rl.value : '', rp: rp ? rp.value : '', rdesc: rdesc ? rdesc.value : '' };
	});
}

function restoreExpandedInputs() {
	for (const [id, vals] of Object.entries(expandedInputs)) {
		const rd = document.getElementById('rd-' + id);
		const rl = document.getElementById('rl-' + id);
		const rp = document.getElementById('rp-' + id);
		const rdesc = document.getElementById('rdesc-' + id);
		if (rd && vals.rd !== undefined) rd.value = vals.rd;
		if (rl && vals.rl !== undefined) rl.value = vals.rl;
		if (rp && vals.rp !== undefined) rp.value = vals.rp;
		if (rdesc && vals.rdesc !== undefined) rdesc.value = vals.rdesc;
	}
	if (activeElementId) {
		const el = document.getElementById(activeElementId);
		if (el) {
			el.focus();
			if (activeElementCursorPos !== null) {
				el.setSelectionRange(activeElementCursorPos, activeElementCursorPos);
			}
		}
		activeElementId = null;
		activeElementCursorPos = null;
	}
}

function clearExpandedInputs() {
  expandedInputs = {};
}

async function loadVersion() {
  try {
    const res = await xhr('GET', '/version');
    if (res.ok) {
      const data = await res.json();
      const pill = document.getElementById('versionPill');
      if (pill) pill.textContent = data.version || '';
    }
  } catch (e) {}
}

async function saveConfig(e) {
	e.preventDefault();
	try {
	const cfg = {
		interface: document.getElementById('iInterface').value,
		port: parseInt(document.getElementById('iPort').value),
		endpoint: document.getElementById('iEndpoint').value,
		dns: document.getElementById('iDns').value,
		subnet: document.getElementById('iSubnet').value,
		wanInterface: document.getElementById('wanInterface').value,
		postUp: document.getElementById('iPostUp').value,
		postDown: document.getElementById('iPostDown').value,
		tlsEnabled: document.getElementById('iTLSEnabled').checked,
		tlsHost: document.getElementById('iTLSHost').value,
		tlsCache: document.getElementById('iTLSCache').value,
	};
	const res = await xhr('POST', '/config/save', cfg);
	if (res.ok) {
		const btn = document.getElementById('saveConfigBtn');
		if (btn) {
			const oldText = btn.textContent;
			btn.textContent = 'Сохранено';
			btn.classList.add('copied');
			setTimeout(() => {
				btn.textContent = oldText;
				btn.classList.remove('copied');
			}, 2000);
		}
		const interfaceNameEl = document.getElementById('interfaceName');
		if (interfaceNameEl) interfaceNameEl.textContent = cfg.interface ? '(' + cfg.interface + ')' : '(wg0)';
		const interfaceIPEl = document.getElementById('interfaceIP');
		if (interfaceIPEl) {
			const ip = cfg.interfaceIP || '';
			interfaceIPEl.textContent = ip ? '(' + ip + ')' : '';
		}
	}
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

async function createBackup() {
  try {
    const res = await fetch('/api/backup/create', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + (getToken() || '') }
    });
    if (!res.ok) {
      alert('Ошибка создания бэкапа: ' + (await res.text()));
      return;
    }
    const blob = await res.blob();
    const disposition = res.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^"]+)"?/);
    const filename = match ? match[1] : 'ncmanager-backup.zip';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    const status = document.getElementById('backupStatus');
    if (status) {
      status.textContent = 'Бэкап скачан: ' + filename + ' (' + (blob.size/1024|0) + ' KB)';
      setTimeout(() => status.textContent = '', 5000);
    }
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

function showRestoreModal() {
  const modal = document.getElementById('restoreModal');
  const input = document.getElementById('restoreFile');
  const log = document.getElementById('restoreLog');
  if (modal) modal.classList.add('show');
  if (input) input.value = '';
  if (log) { log.style.display = 'none'; log.textContent = ''; }
}

function hideRestoreModal() {
  const modal = document.getElementById('restoreModal');
  if (modal) modal.classList.remove('show');
}

async function restoreBackup() {
  const input = document.getElementById('restoreFile');
  const log = document.getElementById('restoreLog');
  if (!input || !input.files || input.files.length === 0) {
    alert('Выберите файл бэкапа');
    return;
  }
  if (log) { log.style.display = 'block'; log.textContent = 'Восстановление...'; }
  try {
    const fd = new FormData();
    fd.append('backup', input.files[0]);
    const res = await fetch('/api/backup/restore', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + (getToken() || '') },
      body: fd
    });
    const data = await res.json();
    if (res.ok && data.status === 'ok') {
      alert('Восстановлено файлов: ' + data.restored.length);
      if (log) log.textContent = 'Восстановлено: ' + data.restored.join('\n');
      hideRestoreModal();
    } else {
      alert('Ошибка восстановления: ' + (data.error || JSON.stringify(data)));
    }
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

async function init() {
	console.log('>>> INIT START <<<');
	hideLogin();
	await loadVersion();
	const cfg = await loadConfig();
	document.getElementById('iInterface').value = cfg.interface || 'wg0';
	const interfaceNameEl = document.getElementById('interfaceName');
	if (interfaceNameEl) interfaceNameEl.textContent = cfg.interface ? '(' + cfg.interface + ')' : '(wg0)';
	const interfaceIPEl = document.getElementById('interfaceIP');
	if (interfaceIPEl) {
		const ip = cfg.interfaceIP || '';
		interfaceIPEl.textContent = ip ? '(' + ip + ')' : '';
	}
	document.getElementById('iPort').value = cfg.port || 51820;
	document.getElementById('iEndpoint').value = cfg.endpoint || '';
	document.getElementById('iDns').value = cfg.dns || '1.1.1.1';
	document.getElementById('iSubnet').value = cfg.subnet || '10.0.0.0/24';
	document.getElementById('iPostUp').value = cfg.postUp || '';
	document.getElementById('iPostDown').value = cfg.postDown || '';
	document.getElementById('iTLSEnabled').checked = cfg.tlsEnabled || false;
	document.getElementById('iTLSHost').value = cfg.tlsHost || '';
	document.getElementById('iTLSCache').value = cfg.tlsCache || 'data/tls-cache';
	document.getElementById('wanInterface').value = cfg.wanInterface || '';
	document.getElementById('serverForm').addEventListener('submit', saveConfig);
	await loadInterfaces();
	await loadAmneziaStatus();
	await loadPresets();
	const saved = localStorage.getItem('ncmanager_tab') || 'peers';
	const tabBtn = Array.from(document.querySelectorAll('.nav-link')).find(b => b.getAttribute('data-tab') === saved) || document.querySelector('.nav-link');
	switchTab(saved, tabBtn);
	initTheme();
	startAutoRefresh();
	refresh();
}

function startAutoRefresh() {
	stopAutoRefresh();
	refreshTimer = setInterval(() => {
		if (!document.getElementById('qrModal').classList.contains('show') &&
			!document.getElementById('textModal').classList.contains('show')) {
			if (currentTab === 'logs') {
				loadLogs();
			} else {
				refresh();
			}
		}
	}, 5000);
	startRouterCheck();
}

function stopAutoRefresh() {
	if (refreshTimer) {
		clearInterval(refreshTimer);
		refreshTimer = null;
	}
}

function startRouterCheck() {
	if (routerCheckTimer) clearInterval(routerCheckTimer);
	routerCheckTimer = setInterval(() => {
		checkAllRouters();
	}, 30000);
	checkAllRouters();
}

function stopRouterCheck() {
	if (routerCheckTimer) {
		clearInterval(routerCheckTimer);
		routerCheckTimer = null;
	}
}

let logFollowing = true;

async function loadLogs() {
	try {
		const log = document.getElementById('logOutput');
		if (log) {
			const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 60;
			logFollowing = atBottom;
		}
		const res = await xhr('GET', '/logs');
		if (res.ok) {
			document.getElementById('logOutput').textContent = res.text();
			if (logFollowing) {
				const log = document.getElementById('logOutput');
				log.scrollTop = log.scrollHeight;
			}
		} else {
			document.getElementById('logOutput').textContent = 'Ошибка: ' + res.text();
		}
	} catch (e) {
		document.getElementById('logOutput').textContent = 'Ошибка: ' + e.message;
	}
}

document.getElementById('loginForm').addEventListener('submit', function(e) {
	e.preventDefault();
	login();
});
document.getElementById('changePasswordForm').addEventListener('submit', function(e) {
	e.preventDefault();
	changePassword();
});

window.addEventListener('DOMContentLoaded', async function() {
	// Load version immediately (public endpoint)
	await loadVersion();
	
	try {
		const res = await xhr('GET', '/status');
		if (res.ok) {
			await init();
		} else {
			showLogin();
		}
	} catch (e) {
		showLogin();
	}

	const log = document.getElementById('logOutput');
	if (log) {
		log.addEventListener('scroll', () => {
			logFollowing = log.scrollHeight - log.scrollTop - log.clientHeight < 60;
		});
	}
});

async function loadInterfaces() {
  try {
    const res = await xhr('GET', '/interfaces');
    if (res.ok) {
      const ifaces = await res.json();
      const sel = document.getElementById('wanInterface');
      if (sel) {
        sel.innerHTML = ifaces.map(i => `<option value="${escapeHtml(i)}">${escapeHtml(i)}</option>`).join('');
      }
    }
  } catch (e) {
    console.error('loadInterfaces failed:', e);
  }
  const cfg = await loadConfig();
  const sel = document.getElementById('wanInterface');
  if (sel && cfg.wanInterface) {
    sel.value = cfg.wanInterface;
  }
}

async function saveWanInterface() {
  const iface = document.getElementById('wanInterface').value;
  const cfg = await loadConfig();
  cfg.wanInterface = iface;
  const res = await xhr('POST', '/config/save', cfg);
  if (res.ok) {
    const status = document.getElementById('wanStatus');
    if (status) {
      status.textContent = '✅ Сохранено';
      setTimeout(() => status.textContent = '', 3000);
    }
  }
}

async function loadAmneziaStatus() {
  try {
    const res = await xhr('GET', '/amnezia/status');
    if (res.ok) {
      const data = await res.json();
      const statusEl = document.getElementById('amneziaStatus');
      const btn = document.getElementById('amneziaInstallBtn');
      if (data.installed) {
        if (statusEl) statusEl.textContent = '✅ Amnezia WG установлен' + (data.version ? ' (' + data.version + ')' : '');
        if (btn) btn.style.display = 'none';
      } else {
        if (statusEl) statusEl.textContent = '❌ Amnezia WG не установлен';
        if (btn) btn.style.display = 'inline-block';
      }
      if (data.installStatus === 'running') {
        showAmneziaModal();
      }
      const logEl = document.getElementById('amneziaInstallLog');
      const installStatusEl = document.getElementById('amneziaInstallStatus');
      if (logEl && data.installLogTail) {
        logEl.value = data.installLogTail;
        logEl.scrollTop = logEl.scrollHeight;
      }
      if (installStatusEl) {
        const map = {running:'⏳ Установка...', completed:'✅ Установка завершена', failed:'❌ Ошибка установки', idle:''};
        installStatusEl.textContent = map[(data.installStatus || '').trim()] || '';
      }
      if (data.installStatus === 'completed' || data.installStatus === 'failed') {
        if (window._amneziaPoll) clearInterval(window._amneziaPoll);
        window._amneziaPoll = null;
      }
      if (data.installStatus === 'completed') {
        setTimeout(closeAmneziaModal, 8000);
      }
      setTimeout(loadAmneziaStatus, 4000);
    }
  } catch (e) {
    console.error('loadAmneziaStatus failed:', e);
  }
}

function showAmneziaModal() {
  const m = document.getElementById('amneziaInstallModal');
  if (m) m.classList.add('show');
}

function closeAmneziaModal() {
  const m = document.getElementById('amneziaInstallModal');
  if (m) m.classList.remove('show');
}

async function loadAmneziaInterfaces() {
  try {
    const res = await xhr('GET', '/amnezia/interfaces');
    if (res.ok) {
      const ifaces = await res.json();
      renderAmneziaInterfaces(ifaces);
    }
  } catch (e) {
    console.error('loadAmneziaInterfaces failed:', e);
  }
}

function formatRate(bytesPerSec) {
  if (!isFinite(bytesPerSec) || bytesPerSec < 0) return '—';
  const v = bytesPerSec * 8 / 1000;
  const units = ['Kbit/s', 'Mbit/s', 'Gbit/s'];
  let u = 0;
  let val = v;
  while (val >= 1000 && u < units.length - 1) { val /= 1000; u++; }
  return val.toFixed(u === 0 ? 0 : 1) + ' ' + units[u];
}

function formatBytesStatic(v) {
  if (!isFinite(v) || v < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let u = 0;
  let val = v;
  while (val >= 1024 && u < units.length - 1) { val /= 1024; u++; }
  return (u === 0 ? Math.round(val) : val.toFixed(1)) + ' ' + units[u];
}

function buildAmneziaSparkline(rxRates, txRates) {
  const width = 300;
  const padTop = 6;
  const padBottom = 6;
  const height = 24;
  const innerH = height - padTop - padBottom;
  const rx = rxRates || [];
  const tx = txRates || [];
  const n = Math.min(rx.length, tx.length);
  if (n < 2) {
    return '<svg class="awg-sparkline" viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none"><line x1="0" x2="' + width + '" y1="' + (height - padBottom) + '" y2="' + (height - padBottom) + '" stroke="var(--color-border-hover)" stroke-width="1" opacity="0.7"/></svg>';
  }
  let maxVal = 1;
  for (let i = 0; i < n; i++) {
    const rv = rx[i] || 0;
    const tv = tx[i] || 0;
    if (rv > maxVal) maxVal = rv;
    if (tv > maxVal) maxVal = tv;
  }
  function rateToY(rate) { return padTop + innerH * (1 - rate / maxVal); }
  function buildPath(rates, color, opacity) {
    if (n < 2) return '';
    const step = width / (n - 1);
    const pts = [];
    for (let i = 0; i < n; i++) pts.push([i * step, rateToY(rates[i] || 0)]);
    let d = 'M' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1);
    const tension = 0.5;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = pts[Math.min(pts.length - 1, i + 2)];
      const cp1x = p1[0] + ((p2[0] - p0[0]) / 6) * tension;
      const cp1y = p1[1] + ((p2[1] - p0[1]) / 6) * tension;
      const cp2x = p2[0] - ((p3[0] - p1[0]) / 6) * tension;
      const cp2y = p2[1] - ((p3[1] - p1[1]) / 6) * tension;
      d += ' C' + cp1x.toFixed(1) + ',' + cp1y.toFixed(1) + ' ' + cp2x.toFixed(1) + ',' + cp2y.toFixed(1) + ' ' + p2[0].toFixed(1) + ',' + p2[1].toFixed(1);
    }
    return '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-opacity="' + opacity + '" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"/>';
  }
  function buildArea(rates, color) {
    if (n < 2) return '';
    const baseY = (height - padBottom).toFixed(1);
    const step = width / (n - 1);
    const pts = [];
    for (let i = 0; i < n; i++) pts.push([i * step, rateToY(rates[i] || 0)]);
    let d = 'M' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1);
    const tension = 0.5;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = pts[Math.min(pts.length - 1, i + 2)];
      const cp1x = p1[0] + ((p2[0] - p0[0]) / 6) * tension;
      const cp1y = p1[1] + ((p2[1] - p0[1]) / 6) * tension;
      const cp2x = p2[0] - ((p3[0] - p1[0]) / 6) * tension;
      const cp2y = p2[1] - ((p3[1] - p1[1]) / 6) * tension;
      d += ' C' + cp1x.toFixed(1) + ',' + cp1y.toFixed(1) + ' ' + cp2x.toFixed(1) + ',' + cp2y.toFixed(1) + ' ' + p2[0].toFixed(1) + ',' + p2[1].toFixed(1);
    }
    d += ' L' + (width).toFixed(1) + ',' + baseY + ' L0,' + baseY + ' Z';
    return '<path d="' + d + '" fill="url(#' + color + '-grad)" opacity="0.55"/>';
  }
  const rxLine = buildPath(rx, 'var(--color-accent)', '1');
  const txLine = buildPath(tx, 'var(--color-success)', '0.95');
  const rxArea = buildArea(rx, 'awg-rx');
  const txArea = buildArea(tx, 'awg-tx');
  return '<svg class="awg-sparkline" viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none"><defs><linearGradient id="awg-rx-grad" x1="0" y1="' + padTop + '" x2="0" y2="' + (height - padBottom) + '" gradientUnits="userSpaceOnUse"><stop offset="0%" stop-color="var(--color-accent)" stop-opacity="0.55"/><stop offset="100%" stop-color="var(--color-accent)" stop-opacity="0"/></linearGradient><linearGradient id="awg-tx-grad" x1="0" y1="' + padTop + '" x2="0" y2="' + (height - padBottom) + '" gradientUnits="userSpaceOnUse"><stop offset="0%" stop-color="var(--color-success)" stop-opacity="0.55"/><stop offset="100%" stop-color="var(--color-success)" stop-opacity="0"/></linearGradient></defs>' + rxArea + txArea + rxLine + txLine + '</svg>';
}

let awgChartPeriod = '1h';
let awgChartName = '';
let awgChartPoints = [];
let awgChartRxRates = [];
let awgChartTxRates = [];
const AWG_CHART_W = 840;

let awgPingStatus = {}; // name -> {checking, hasResult, connected, latency, text}
let awgLastIfaces = []; // cached ifaces for ping re-render
const awgPingTimers = new Map();

function scheduleAmneziaPing(name, delay) {
  if (awgPingTimers.has(name)) clearTimeout(awgPingTimers.get(name));
  const handle = setTimeout(function() {
    awgPingTimers.delete(name);
    checkAmneziaPing(name);
  }, delay || 300);
  awgPingTimers.set(name, handle);
}

function refreshAmneziaPings() {
  if (!awgLastIfaces || !awgLastIfaces.length) return;
  for (const iface of awgLastIfaces) {
    if (iface.running !== 'true') continue;
    const st = awgPingStatus[iface.name];
    if (!st || !st.hasResult) {
      scheduleAmneziaPing(iface.name, 0);
    }
  }
}

let awgPingNonce = 0;
let awgCheckingPings = new Set();

async function checkAmneziaPing(name) {
  if (awgCheckingPings.has(name)) return;
  awgCheckingPings.add(name);
  awgPingStatus[name] = awgPingStatus[name] || {};
  awgPingStatus[name].checking = true;
  renderAmneziaInterfaces(awgLastIfaces);
  try {
    const res = await xhr('GET', '/amnezia/interface/' + encodeURIComponent(name) + '/ping');
    if (res.ok) {
      const data = res.json();
      awgPingStatus[name] = {
        checking: false,
        hasResult: true,
        connected: !!data.connected,
        latency: data.latency || 0,
        text: data.text || '—'
      };
    } else {
      awgPingStatus[name] = { checking: false, hasResult: true, connected: false, latency: 0, text: 'err' };
    }
  } catch (e) {
    awgPingStatus[name] = { checking: false, hasResult: true, connected: false, latency: 0, text: 'err' };
  }
  awgCheckingPings.delete(name);
  renderAmneziaInterfaces(awgLastIfaces);
  scheduleAmneziaRefresh();
}

let awgPingRefreshHandle = null;
function scheduleAmneziaRefresh() {
  if (awgPingRefreshHandle) clearTimeout(awgPingRefreshHandle);
  awgPingRefreshHandle = setTimeout(function() {
    refreshAmneziaPings();
  }, 5000);
}

function cancelAmneziaPingRefresh() {
  if (awgPingRefreshHandle) clearTimeout(awgPingRefreshHandle);
  awgPingRefreshHandle = null;
  for (const [name, handle] of awgPingTimers) {
    clearTimeout(handle);
  }
  awgPingTimers.clear();
}
const AWG_CHART_PAD_TOP = 16;
const AWG_CHART_PAD_BOTTOM = 32;
const AWG_CHART_HEIGHT = 220;
let awgChartMaxRate = 1;

function awgTier(ms) {
  if (ms < 100) return 'tier-good';
  if (ms < 150) return 'tier-warn';
  if (ms < 220) return 'tier-high';
  return 'tier-bad';
}

async function checkAmneziaPing(name) {
  awgPingStatus[name] = awgPingStatus[name] || {};
  awgPingStatus[name].checking = true;
  renderAmneziaInterfaces(awgLastIfaces);
  try {
    const res = await xhr('GET', '/amnezia/interface/' + encodeURIComponent(name) + '/ping');
    if (res.ok) {
      const data = res.json();
      awgPingStatus[name] = {
        checking: false,
        hasResult: true,
        connected: !!data.connected,
        latency: data.latency || 0,
        text: data.text || '—'
      };
    } else {
      awgPingStatus[name] = { checking: false, hasResult: true, connected: false, latency: 0, text: 'err' };
    }
  } catch (e) {
    awgPingStatus[name] = { checking: false, hasResult: true, connected: false, latency: 0, text: 'err' };
  }
  renderAmneziaInterfaces(awgLastIfaces);
}

function openAwgChartModal(name) {
  awgChartName = name;
  awgChartPeriod = '1h';
  awgChartPoints = [];
  awgChartRxRates = [];
  awgChartTxRates = [];
  const modal = document.getElementById('awgChartModal');
  if (!modal) return;
  modal.classList.add('show');
  document.getElementById('awgChartTitle').textContent = 'Трафик: ' + name;
  document.querySelectorAll('.awg-chart-period-btn').forEach(function(btn) {
    btn.classList.toggle('active', btn.dataset.period === '1h');
  });
  renderAwgChart(name, '1h');
}

function closeAwgChartModal() {
  const modal = document.getElementById('awgChartModal');
  if (modal) modal.classList.remove('show');
  awgChartName = '';
}

const PERIOD_LABELS = { '1h': 'последний час', '3h': 'последние 3 часа', '24h': 'последние сутки' };

async function renderAwgChart(name, period) {
  const container = document.getElementById('awgChartContainer');
  const overlay = document.getElementById('awgChartOverlay');
  if (!container) return;
  if (overlay) overlay.style.display = 'none';
  container.innerHTML = '<p style="color:var(--color-text-muted);padding:16px">Загрузка...</p>';
  try {
    const res = await xhr('GET', '/amnezia/interface/' + encodeURIComponent(name) + '/stats?period=' + encodeURIComponent(period));
    if (!res.ok) throw new Error('Failed to load stats');
    const data = res.json();
    const points = data.points || [];
    if (points.length < 2) {
      container.innerHTML = '<p style="color:var(--color-text-muted);padding:16px">Недостаточно данных за выбранный период</p>';
      return;
    }
    const namePill = document.getElementById('awgChartNamePill');
    if (namePill) namePill.textContent = name;
    const periodPill = document.getElementById('awgChartPeriodPill');
    if (periodPill) periodPill.textContent = PERIOD_LABELS[period] || period;

    const rxRates = [];
    const txRates = [];
    for (const pt of points) { rxRates.push(pt.rx || 0); txRates.push(pt.tx || 0); }
    awgChartPoints = points;
    awgChartRxRates = rxRates;
    awgChartTxRates = txRates;
    const n = points.length;
    const width = 840;
    const padTop = 16;
    const padBottom = 32;
    const height = 220;
    const innerH = height - padTop - padBottom;
    let maxRate = 1;
    for (let i = 0; i < n; i++) {
      if (rxRates[i] > maxRate) maxRate = rxRates[i];
      if (txRates[i] > maxRate) maxRate = txRates[i];
    }
    awgChartMaxRate = maxRate;
    function rateToY(rate) { return padTop + innerH * (1 - rate / maxRate); }
    function indexToX(i) { return (i * (width - padBottom)) / (n - 1); }
    function smoothPath(pts) {
      if (pts.length < 2) return '';
      if (pts.length === 2) return 'M' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1) + ' L' + pts[1][0].toFixed(1) + ',' + pts[1][1].toFixed(1);
      const tension = 0.5;
      let d = 'M' + pts[0][0].toFixed(1) + ',' + pts[0][1].toFixed(1);
      for (let i = 0; i < pts.length - 1; i++) {
        const p0 = pts[Math.max(0, i - 1)];
        const p1 = pts[i];
        const p2 = pts[i + 1];
        const p3 = pts[Math.min(pts.length - 1, i + 2)];
        const cp1x = p1[0] + ((p2[0] - p0[0]) / 6) * tension;
        const cp1y = p1[1] + ((p2[1] - p0[1]) / 6) * tension;
        const cp2x = p2[0] - ((p3[0] - p1[0]) / 6) * tension;
        const cp2y = p2[1] - ((p3[1] - p1[1]) / 6) * tension;
        d += ' C' + cp1x.toFixed(1) + ',' + cp1y.toFixed(1) + ' ' + cp2x.toFixed(1) + ',' + cp2y.toFixed(1) + ' ' + p2[0].toFixed(1) + ',' + p2[1].toFixed(1);
      }
      return d;
    }
    function buildLine(rates) {
      const pts = [];
      for (let i = 0; i < n; i++) pts.push([indexToX(i), rateToY(rates[i] || 0)]);
      return smoothPath(pts);
    }
    const rxLine = buildLine(rxRates);
    const txLine = buildLine(txRates);
    function buildArea(linePath) {
      const endX = width.toFixed(1);
      const startX = '0';
      const baseY = (height - padBottom).toFixed(1);
      return linePath + ' L' + endX + ',' + baseY + ' L' + startX + ',' + baseY + ' Z';
    }
    const rxArea = buildArea(rxLine);
    const txArea = buildArea(txLine);

    const fmtTime = function(ts) {
      if (!ts && ts !== 0) return '—';
      const d = new Date(ts * 1000);
      if (isNaN(d.getTime())) return '—';
      return d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0') + ':' + d.getSeconds().toString().padStart(2,'0');
    };
    const startT = fmtTime(points[0].ts);
    const endT = fmtTime(points[points.length - 1].ts);

    const maxRateEl = document.getElementById('awgChartMaxRate');
    if (maxRateEl) maxRateEl.textContent = formatRate(maxRate);
    const timeStartEl = document.getElementById('awgChartTimeStart');
    if (timeStartEl) timeStartEl.textContent = startT;
    const timeEndEl = document.getElementById('awgChartTimeEnd');
    if (timeEndEl) timeEndEl.textContent = endT;

    const peak = data.stats ? data.stats.peakRate : 0;
    const avgRx = data.stats ? data.stats.avgRx : 0;
    const avgTx = data.stats ? data.stats.avgTx : 0;
    const curRx = data.stats ? data.stats.currentRx : (rxRates.length ? rxRates[rxRates.length-1] : 0);
    const curTx = data.stats ? data.stats.currentTx : (txRates.length ? txRates[txRates.length-1] : 0);

    const trafficRxEl = document.getElementById('awgChartTrafficRx');
    if (trafficRxEl) trafficRxEl.textContent = '↓ ' + formatRate(curRx);
    const trafficTxEl = document.getElementById('awgChartTrafficTx');
    if (trafficTxEl) trafficTxEl.textContent = '↑ ' + formatRate(curTx);
    const peakEl = document.getElementById('awgChartPeak');
    if (peakEl) peakEl.textContent = formatRate(peak);
    const avgRxEl = document.getElementById('awgChartAvgRx');
    if (avgRxEl) avgRxEl.textContent = '↓ ' + formatRate(avgRx);
    const avgTxEl = document.getElementById('awgChartAvgTx');
    if (avgTxEl) avgTxEl.textContent = '↑ ' + formatRate(avgTx);

    const legRxEl = document.getElementById('awgChartLegRx');
    if (legRxEl) legRxEl.textContent = formatRate(curRx);
    const legTxEl = document.getElementById('awgChartLegTx');
    if (legTxEl) legTxEl.textContent = formatRate(curTx);

    container.innerHTML = '<svg viewBox="0 0 ' + width + ' ' + height + '" preserveAspectRatio="none" style="display:block;width:100%;height:100%" onmousemove="awgChartHover(event)" onmouseleave="awgChartLeave()"><defs><linearGradient id="awg-rx-grad" x1="0" y1="' + padTop + '" x2="0" y2="' + (height - padBottom) + '" gradientUnits="userSpaceOnUse"><stop offset="0%" stop-color="var(--color-accent)" stop-opacity="0.55"/><stop offset="100%" stop-color="var(--color-accent)" stop-opacity="0"/></linearGradient><linearGradient id="awg-tx-grad" x1="0" y1="' + padTop + '" x2="0" y2="' + (height - padBottom) + '" gradientUnits="userSpaceOnUse"><stop offset="0%" stop-color="var(--color-success)" stop-opacity="0.55"/><stop offset="100%" stop-color="var(--color-success)" stop-opacity="0"/></linearGradient></defs><path d="' + rxArea + '" fill="url(#awg-rx-grad)"/><path d="' + rxLine + '" fill="none" stroke="var(--color-accent)" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/><path d="' + txArea + '" fill="url(#awg-tx-grad)"/><path d="' + txLine + '" fill="none" stroke="var(--color-success)" stroke-width="1.4" stroke-linejoin="round" stroke-linecap="round" opacity="0.95"/><g id="awgChartCrosshair" style="display:none"><line id="awgCrossV" x1="0" y1="' + padTop + '" x2="0" y2="' + (height - padBottom) + '" stroke="var(--color-text-muted)" stroke-width="0.6" stroke-dasharray="2,2" opacity="0.8"/><circle id="awgCrossRx" cx="0" cy="0" r="3.5" fill="var(--color-accent)" stroke="var(--color-bg-secondary)" stroke-width="1"/><circle id="awgCrossTx" cx="0" cy="0" r="3.5" fill="var(--color-success)" stroke="var(--color-bg-secondary)" stroke-width="1"/></g><line x1="0" x2="' + width + '" y1="' + (height - padBottom) + '" y2="' + (height - padBottom) + '" stroke="var(--color-border-hover)" stroke-width="1" opacity="0.7"/></svg>';
  } catch (e) {
    container.innerHTML = '<p style="color:var(--color-error);padding:16px">Ошибка загрузки графика</p>';
  }
}

function awgChartHover(e) {
  const svg = e.target.closest('svg');
  if (!svg || awgChartPoints.length < 2) return;
  const rect = svg.getBoundingClientRect();
  const mouseX = e.clientX - rect.left;
  const width = AWG_CHART_W;
  const vbX = mouseX * (width / rect.width);
  const innerW = width;
  const step = innerW / (awgChartPoints.length - 1);
  const idx = Math.max(0, Math.min(awgChartPoints.length - 1, Math.round(vbX / step)));
  const x = idx * step;
  const innerH = AWG_CHART_HEIGHT - AWG_CHART_PAD_TOP - AWG_CHART_PAD_BOTTOM;
  const rxY = AWG_CHART_PAD_TOP + innerH * (1 - (awgChartRxRates[idx] || 0) / awgChartMaxRate);
  const txY = AWG_CHART_PAD_TOP + innerH * (1 - (awgChartTxRates[idx] || 0) / awgChartMaxRate);

  const cross = document.getElementById('awgChartCrosshair');
  if (cross) cross.style.display = 'block';
  const vLine = document.getElementById('awgCrossV');
  if (vLine) { vLine.setAttribute('x1', x); vLine.setAttribute('x2', x); }
  const rxDot = document.getElementById('awgCrossRx');
  if (rxDot) { rxDot.setAttribute('cx', x); rxDot.setAttribute('cy', rxY); }
  const txDot = document.getElementById('awgCrossTx');
  if (txDot) { txDot.setAttribute('cx', x); txDot.setAttribute('cy', txY); }

  const tooltip = document.getElementById('awgChartTooltip');
  if (!tooltip) return;
  const rx = awgChartRxRates[idx] || 0;
  const tx = awgChartTxRates[idx] || 0;
  const ts = awgChartPoints[idx] ? awgChartPoints[idx].ts : 0;
  const d = new Date(ts * 1000);
  const timeStr = d.getHours().toString().padStart(2,'0') + ':' + d.getMinutes().toString().padStart(2,'0') + ':' + d.getSeconds().toString().padStart(2,'0');
  tooltip.innerHTML = '<div style="color:var(--color-text-muted);margin-bottom:2px">' + timeStr + '</div><div style="color:var(--color-accent)">↓ ' + formatRate(rx) + '</div><div style="color:var(--color-success)">↑ ' + formatRate(tx) + '</div>';
  tooltip.style.display = 'block';
  tooltip.style.left = Math.min(vbX + 12, rect.width - 140) + 'px';
  tooltip.style.top = '40px';
}

function awgChartLeave() {
  const tooltip = document.getElementById('awgChartTooltip');
  if (tooltip) tooltip.style.display = 'none';
  const cross = document.getElementById('awgChartCrosshair');
  if (cross) cross.style.display = 'none';
}

function selectAwgChartPeriod(period, btn) {
  awgChartPeriod = period;
  document.querySelectorAll('.awg-chart-period-btn').forEach(function(b) { b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  if (awgChartName) renderAwgChart(awgChartName, period);
}

function renderAmneziaInterfaces(ifaces) {
  awgLastIfaces = ifaces || [];
  const list = document.getElementById('amneziaInterfaceList');
  if (!list) return;
  if (!ifaces || !ifaces.length) {
    list.innerHTML = '<p style="color:#64748b">Нет импортированных интерфейсов</p>';
    return;
  }
  let html = '';
  for (const iface of ifaces) {
    const running = iface.running === 'true';
    const ledClass = running ? 'led-green' : 'led-gray';
    const rawName = iface.name;
    const name = escapeHtml(iface.name);
    const addr = escapeHtml(iface.address || '—');
    const endpoint = escapeHtml(iface.endpoint || '');
    const hs = escapeHtml(iface.handshake || '—');
    const rates = getAmneziaSparklineRates(iface.name);
    const sparkline = buildAmneziaSparkline(rates.rx, rates.tx);
    const currentRxRate = rates.rx.length ? rates.rx[rates.rx.length - 1] : 0;
    const currentTxRate = rates.tx.length ? rates.tx[rates.tx.length - 1] : 0;

    const pingState = awgPingStatus[name] || {};
    const pingChecking = pingState.checking;
    const pingConnected = pingState.connected;
    const pingLatency = pingState.latency;

    let pingLabel, pingTierClass, pingTitle, pingDisabled, pingSpinning, pingShowIcon;
    if (pingChecking) {
      pingLabel = '...';
      pingTierClass = '';
      pingTitle = 'Проверить связь';
      pingDisabled = true;
      pingSpinning = true;
      pingShowIcon = true;
    } else if (pingConnected) {
      const ms = Math.round(pingLatency);
      pingLabel = ms + 'ms';
      pingTierClass = awgTier(ms);
      pingTitle = 'Проверить связь';
      pingDisabled = false;
      pingSpinning = false;
      pingShowIcon = true;
    } else if (pingState.hasResult) {
      pingLabel = 'Нет связи';
      pingTierClass = 'tier-bad';
      pingTitle = 'Нет связи. Нажать для проверки';
      pingDisabled = false;
      pingSpinning = false;
      pingShowIcon = false;
    } else {
      pingLabel = '...';
      pingTierClass = '';
      pingTitle = 'Проверить связь';
      pingDisabled = false;
      pingSpinning = false;
      pingShowIcon = false;
    }

    html += '<div class="awg-card view-dense" data-name="' + rawName.replace(/"/g, '&quot;') + '">' +
      '<div class="awg-card-header">' +
        '<div class="awg-card-title-group">' +
          '<div class="awg-card-title-row">' +
            '<span class="led ' + ledClass + '"></span>' +
            '<span class="awg-card-name">' + name + '</span>' +
          '</div>' +
          '<div class="awg-card-meta-tags">' +
            '<span class="awg-iface-tag" title="' + escapeHtml(iface.name) + '">' + escapeHtml(iface.name) + '</span>' +
          '</div>' +
        '</div>' +
        '<div class="awg-card-toolbar">' +
          '<div class="awg-toolbar-row">' +
            '<label class="toggle-switch" title="' + (running ? 'Остановить' : 'Запустить') + '">' +
              '<input type="checkbox" ' + (running ? 'checked' : '') + ' onchange="manageAmneziaInterface(\'' + rawName + '\',' + (running ? '\'down\'' : '\'up\'') + ')">' +
              '<span class="toggle-slider"></span>' +
            '</label>' +
          '</div>' +
          (running ?
            '<button type="button" class="ping-btn ' + pingTierClass + (pingSpinning ? ' spinning' : '') + ' force-border" onclick="checkAmneziaPing(\'' + rawName + '\')" title="' + pingTitle + '" ' + (pingDisabled ? 'disabled' : '') + '>' +
              pingLabel +
              (pingShowIcon ? '<span class="refresh-icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16"/><path d="M16 16h5v5"/></svg></span>' : '') +
            '</button>'
          : '') +
        '</div>' +
      '</div>' +
      '<div class="awg-card-details">' +
        '<div class="awg-card-kv-cols">' +
          '<div class="awg-card-kv-col">' +
            '<div class="awg-kv"><span class="awg-kv-label">Адрес</span><span class="awg-kv-value">' + addr + '</span></div>' +
            (endpoint ? '<div class="awg-kv"><span class="awg-kv-label">Endpoint</span><span class="awg-kv-value">' + endpoint + '</span></div>' : '') +
          '</div>' +
          '<div class="awg-card-kv-col awg-card-kv-col-right">' +
            '<div class="awg-kv"><span class="awg-kv-label">Handshake</span><span class="awg-kv-value">' + hs + '</span></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="awg-card-chart" onclick="openAwgChartModal(\'' + rawName + '\')" title="Открыть график трафика" role="button" tabindex="0">' +
        sparkline +
        '<div class="awg-traffic-rates">' +
          '<span class="awg-traffic-rate rx">↓ ' + formatRate(currentRxRate) + '</span>' +
          '<span class="awg-traffic-rate tx">↑ ' + formatRate(currentTxRate) + '</span>' +
        '</div>' +
      '</div>' +
    '</div>';
  }
  list.innerHTML = html;
  if (ifaces && ifaces.length) {
    awgPingNonce++;
    const nonce = awgPingNonce;
    let started = false;
    setTimeout(function() {
      if (nonce !== awgPingNonce) return;
      for (const iface of ifaces) {
        if (iface.running !== 'true') continue;
        const st = awgPingStatus[iface.name];
        if (!st || !st.hasResult) {
          if (!started) { started = true; }
          scheduleAmneziaPing(iface.name, started ? 250 : 0);
        }
      }
    }, 50);
    for (const iface of ifaces) {
      loadAmneziaSparkline(iface.name);
    }
  }
}

async function manageAmneziaInterface(name, action) {
  try {
    const res = await xhr('POST', '/amnezia/interface/' + encodeURIComponent(name) + '/' + action, {});
    if (res.ok) {
      loadAmneziaInterfaces();
    } else {
      alert('Ошибка: ' + (await res.text()));
    }
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}

async function installAmnezia() {
  const btn = document.getElementById('amneziaInstallBtn');
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Установка...';
  }
  showAmneziaModal();
  const logEl = document.getElementById('amneziaInstallLog');
  const statusEl = document.getElementById('amneziaInstallStatus');
  if (logEl) logEl.value = '';
  if (statusEl) statusEl.textContent = '⏳ Установка...';
  try {
    const res = await xhr('POST', '/amnezia/install');
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'started') {
        if (window._amneziaPoll) clearInterval(window._amneziaPoll);
        const poll = setInterval(async () => {
          await loadAmneziaStatus();
        }, 1500);
        window._amneziaPoll = poll;
      }
    }
  } catch (e) {
    alert('Ошибка установки: ' + e.message);
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'Установить Amnezia WG';
    }
    if (statusEl) statusEl.textContent = '❌ Ошибка: ' + e.message;
  }
}

function showImportModal() {
  const m = document.getElementById('amneziaImportModal');
  if (m) m.classList.add('show');
  const nameEl = document.getElementById('amneziaInterfaceName');
  if (nameEl) nameEl.value = '';
  const textEl = document.getElementById('amneziaConfigText');
  if (textEl) textEl.value = '';
}

function closeImportModal() {
  const m = document.getElementById('amneziaImportModal');
  if (m) m.classList.remove('show');
}

async function importAmneziaConfig() {
  const interfaceName = document.getElementById('amneziaInterfaceName');
  const name = interfaceName ? interfaceName.value.trim() : '';
  if (!name) {
    alert('Введите имя интерфейса');
    return;
  }
  const textarea = document.getElementById('amneziaConfigText');
  const configText = textarea ? textarea.value.trim() : '';
  if (!configText) {
    alert('Введите конфигурацию');
    return;
  }
  try {
    const res = await xhr('POST', '/amnezia/import', { name, configText });
    if (res.ok) {
      const data = await res.json();
      const status = document.getElementById('importStatus');
      if (status) {
        status.textContent = 'Импортирован: ' + data.name + ' (' + data.publicKey + ')';
        setTimeout(() => status.textContent = '', 5000);
      }
       closeImportModal();
    } else {
      alert('Ошибка импорта: ' + (await res.text()));
    }
  } catch (e) {
    alert('Ошибка: ' + e.message);
  }
}
