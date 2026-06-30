const API = '/api';
const TOKEN_KEY = 'wg_token';
let currentTab = 'peers';
let previousPeerIds = new Set();
let refreshTimer = null;
let expandedPeers = new Set();
let expandedInputs = {};
let activeElementId = null;
let activeElementCursorStart = null;
let activeElementCursorEnd = null;
let _keeneticPeerId = null;

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
				hideLogin();
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
	setToken('');
	await xhr('POST', '/logout');
	showLogin();
}

function switchTab(name, btn) {
	currentTab = name;
	document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
	if (btn) btn.classList.add('active');
	document.querySelectorAll('[id^="tab-"]').forEach(el => el.style.display = 'none');
	const target = document.getElementById('tab-' + name);
	if (target) target.style.display = '';
	if (name === 'logs') loadLogs();
	if (name === 'dns') loadDnsRoutes();
	if (name === 'waniface') loadAmneziaInterfaces();
	try { localStorage.setItem('ncmanager_tab', name); } catch (e) {}
}

async function loadConfig() {
	return (await xhr('GET', '/config')).json();
}

async function loadPeers() {
	return (await xhr('GET', '/peers')).json();
}

async function loadStatus() {
	return (await xhr('GET', '/status')).json();
}

function renderPeers(peers) {
	const tbody = document.getElementById('peersTable');
	if (!peers.length) {
		tbody.innerHTML = '<p style="color:#64748b;padding:12px">Нет пиров</p>';
		return;
	}
	let html = '<table><thead><tr><th>Имя</th><th>IP</th><th>Создан</th><th>Handshake</th><th>Endpoint</th><th>Трафик</th><th>Действия</th><th></th></tr></thead><tbody>';
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
			<td><span class="peer-name-toggle" onclick="togglePeerDetails('${p.id}', event)" style="cursor:pointer;color:#38bdf8">${escapeHtml(p.name)}</span></td>
			<td><code>${escapeHtml(p.allowedIPs)}</code></td>
			<td>${created}</td>
			<td><span class="peer-age ${status.class}" data-field="handshake" title="${p.lastHandshake && new Date(p.lastHandshake).getTime() >= MIN_REASONABLE_DATE ? new Date(p.lastHandshake).toLocaleString('ru-RU') : 'никогда'}">${status.text} · ${hs}</span></td>
			<td><code>${escapeHtml(endpoint)}</code></td>
			<td data-field="traffic"><span title="↑ ${tx}">↑ ${tx}</span> / <span title="↓ ${rx}">↓ ${rx}</span></td>
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
			<td colspan="8">
				<div class="peer-details-content">
					<h4>Настройки роутера для ${escapeHtml(p.name)}</h4>
					<div class="grid-form">
						<label>Домен<input id="rd-${p.id}" value="${escapeHtml(p.routerDomain || '')}" placeholder="router.local"></label>
						<label>Логин<input id="rl-${p.id}" value="${escapeHtml(p.routerLogin || '')}" placeholder="admin"></label>
						<label>Пароль<span class="pwd-wrap"><input type='password' id='rp-${p.id}' value='${escapeHtml(p.routerPassword || '')}' placeholder='••••••'><button type='button' class='pwd-toggle' onclick="togglePwd('rp-${p.id}', this)" title="Показать/скрыть">👁</button></span></label><label style="grid-column:1/-1">Описание<textarea id='rdesc-${p.id}' rows="4" style="width:100%;padding:6px;border-radius:4px;background:var(--color-bg-primary);color:var(--color-text-primary);border:1px solid var(--color-border);font-family:var(--font-sans);font-size:0.85rem;resize:vertical;min-height:100px" placeholder='Комментарий'>${escapeHtml(p.description || '')}</textarea></label>
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
	const btn = document.getElementById('saveRouterBtn-' + id);
	const oldText = btn ? btn.textContent : 'Сохранить';
	try {
		const res = await xhr('POST', '/peers/update', {
			id: id,
			routerDomain: routerDomain,
			routerLogin: routerLogin,
			routerPassword: routerPassword,
			description: description,
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
let activePresetCategory = 'all';

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
    const isAdded = existingRouteNames.has(p.name);
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
    await xhr('GET', '/dns/routes');
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
		} else {
			updatePeerStats(peers);
		}
		const badge = document.getElementById('statusBadge');
		const btn = document.getElementById('btnToggle');
		if (status.running) {
			badge.textContent = 'Запущен';
			badge.className = 'status-badge up';
			btn.textContent = 'Остановить';
		} else {
			badge.textContent = 'Остановлен';
			badge.className = 'status-badge down';
			btn.textContent = 'Запустить';
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
	}
} catch (e) {
	alert('Ошибка: ' + e.message);
}
}

async function init() {
	console.log('>>> INIT START <<<');
	hideLogin();
	const cfg = await loadConfig();
	document.getElementById('iInterface').value = cfg.interface || 'wg0';
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
	const tabBtn = Array.from(document.querySelectorAll('.tab')).find(b => b.getAttribute('onclick').includes("'" + saved + "'")) || document.querySelector('.tab');
	switchTab(saved, tabBtn);
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
}

function stopAutoRefresh() {
	if (refreshTimer) {
		clearInterval(refreshTimer);
		refreshTimer = null;
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

function renderAmneziaInterfaces(ifaces) {
  const list = document.getElementById('amneziaInterfaceList');
  if (!list) return;
  if (!ifaces || !ifaces.length) {
    list.innerHTML = '<p style="color:#64748b">Нет импортированных интерфейсов</p>';
    return;
  }
  let html = '<table><thead><tr><th>Имя</th><th>Статус</th><th>Адрес</th><th>PublicKey</th><th>Handshake / Ping</th><th>Трафик</th><th>Действия</th></tr></thead><tbody>';
  for (const iface of ifaces) {
    const running = iface.running === 'true';
    const statusText = running ? '🟢 Запущен' : '🔴 Остановлен';
    const statusClass = running ? 'led-green' : 'led-gray';
    const pubKey = iface.publicKey ? iface.publicKey.substring(0, 16) + '...' : '—';
    const addr = iface.address || '—';
    const hs = iface.handshake || '—';
    const ping = iface.ping || '—';
    const rx = iface.rx || '0 B';
    const tx = iface.tx || '0 B';
    html += `<tr>
      <td><code>${escapeHtml(iface.name)}</code></td>
      <td><span class="led ${statusClass}"></span> ${statusText}</td>
      <td><code>${escapeHtml(addr)}</code></td>
      <td><code title="${escapeHtml(iface.publicKey || '')}">${escapeHtml(pubKey)}</code></td>
      <td>${escapeHtml(hs)}<br><span style="color:#38bdf8;font-size:0.85rem">ping: ${escapeHtml(ping)}</span></td>
      <td><span title="↓ ${escapeHtml(rx)}">↓ ${escapeHtml(rx)}</span> / <span title="↑ ${escapeHtml(tx)}">↑ ${escapeHtml(tx)}</span></td>
      <td style="display:flex;gap:4px">
        ${!running ? `<button class="btn-qr" onclick="manageAmneziaInterface('${escapeHtml(iface.name)}','up')" title="Запустить">▶</button>` : ''}
        ${running ? `<button class="btn-dl" onclick="manageAmneziaInterface('${escapeHtml(iface.name)}','down')" title="Остановить">⏸</button>` : ''}
        <button class="btn-del" onclick="manageAmneziaInterface('${escapeHtml(iface.name)}','delete')" title="Удалить">✕</button>
      </td>
    </tr>`;
  }
  html += '</tbody></table>';
  list.innerHTML = html;
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
