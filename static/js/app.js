const API = '/api';
const TOKEN_KEY = 'wg_token';
let currentTab = 'peers';
let refreshTimer = null;
let expandedPeers = new Set();
let expandedInputs = {};
let activeElementId = null;
let activeElementCursorPos = null;
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
			hideLogin();
			await init();
		} else {
			alert('Неверный пароль');
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
		html += `<tr class="${rowClass}">
			<td><span class="peer-name-toggle" onclick="togglePeerDetails('${p.id}', event)" style="cursor:pointer;color:#38bdf8">${escapeHtml(p.name)}</span></td>
			<td><code>${escapeHtml(p.allowedIPs)}</code></td>
			<td>${created}</td>
			<td><span class="peer-age ${status.class}" title="${p.lastHandshake && new Date(p.lastHandshake).getTime() >= MIN_REASONABLE_DATE ? new Date(p.lastHandshake).toLocaleString('ru-RU') : 'никогда'}">${status.text} · ${hs}</span></td>
			<td><code>${escapeHtml(endpoint)}</code></td>
			<td><span title="↑ ${tx}">↑ ${tx}</span> / <span title="↓ ${rx}">↓ ${rx}</span></td>
			<td class="peer-actions">
				<button class="btn-qr" onclick="showQR('${p.id}','${escapeHtml(p.name)}')">QR</button>
				<button class="btn-dl" onclick="showText('${p.id}','${escapeHtml(p.name)}')">📋</button>
				<button class="btn-dl" onclick="downloadConf('${p.id}')">⬇</button>
 			<button class="btn-dl" onclick="configureRouter('${p.id}')" title="Настроить VPN на роутере Keenetic">⚙</button>
 			<button class="btn-dl" onclick="configureDnsRouter('${p.id}')" title="Настроить DNS на роутере Keenetic">🌐</button>
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
						<label>Пароль<input type='password' id='rp-${p.id}' value='${escapeHtml(p.routerPassword || '')}' placeholder='••••••'></label><label>Описание<input id='rdesc-${p.id}' value='${escapeHtml(p.description || '')}' placeholder='Комментарий'></label>
					</div>
 					<button onclick="savePeerRouter('${p.id}')" class="btn-dl" style="margin-top:8px">Сохранить настройки роутера</button>
 					<button onclick="configureRouter('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить VPN</button>
 					<button onclick="configureDnsRouter('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить DNS</button>
 					<button onclick="configureDnsRoutes('${p.id}')" class="btn-qr" style="margin-top:8px;margin-left:8px">Настроить DNS-маршрутизацию</button>
				</div>
			</td>
		</tr>`;
	}
	html += '</tbody></table>';
	tbody.innerHTML = html;
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
	try {
		const res = await xhr('POST', '/peers/update', {
			id: id,
			routerDomain: routerDomain,
			routerLogin: routerLogin,
			routerPassword: routerPassword,
			description: description,
		});
		if (!silent && res.ok) {
			alert('Настройки роутера сохранены');
		}
		return res.ok;
	} catch (e) {
		if (!silent) alert('Ошибка: ' + e.message);
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
		const data = await res.json();
		if (data.status === 'ok') {
			log.textContent += '✅ DNS настроен\n';
			if (data.messages && data.messages.length) {
				for (const msg of data.messages) {
					log.textContent += '   ↳ ' + msg + '\n';
				}
			}
			log.textContent += '\nГотово!\n';
		} else {
			log.textContent += '❌ Ошибка: ' + (data.error || 'неизвестно') + '\n';
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

	try {
		log.textContent += '📡 Подключение к ' + routerDomain + '...\n';
		const res = await xhr('POST', '/peers/keenetic-dns-routes/' + encodeURIComponent(id), { enabled: true });
		const data = await res.json();
		if (data.status === 'ok') {
			log.textContent += '✅ DNS-маршрутизация включена (dns-routes на ' + data.wanIface + ')\n';
			if (data.messages && data.messages.length) {
				for (const msg of data.messages) {
					log.textContent += '   ↳ ' + msg + '\n';
				}
			}
			log.textContent += '\nГотово!\n';
		} else {
			log.textContent += '❌ Ошибка: ' + (data.error || 'неизвестно') + '\n';
		}
	} catch (e) {
		log.textContent += '❌ Ошибка настройки DNS-маршрутизации: ' + e.message + '\n';
	}

	if (closeBtn) closeBtn.style.display = '';
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

function copyText() {
	const text = document.getElementById('textOutput').textContent;
	const btn = event.target;
	const oldText = btn.textContent;
	try {
		navigator.clipboard.writeText(text).then(() => {
			btn.textContent = 'Скопировано';
			setTimeout(() => btn.textContent = oldText, 2000);
		}).catch(() => {
			const el = document.getElementById('textOutput');
			const range = document.createRange();
			range.selectNode(el);
			window.getSelection().removeAllRanges();
			window.getSelection().addRange(range);
			document.execCommand('copy');
			btn.textContent = 'Скопировано';
			setTimeout(() => btn.textContent = oldText, 2000);
		});
	} catch (e) {
		if (btn) btn.textContent = oldText;
	}
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

const DNS_PRESETS = [
  { name: "Anthropic / Claude", domains: [
    'anthropic.com',
    'claude.ai',
    'claude.com'
  ] },
  { name: "Все AI сервисы", domains: [
    'ai.google.dev',
    'alkalicore-pa.clients6.google.com',
    'antigravity-pa.googleapis.com',
    'antigravity.googleapis.com',
    'browser-intake-datadoghq.com',
    'cloudaicompanion.googleapis.com',
    'cloudcode-pa.googleapis.com',
    'copilot-proxy.githubusercontent.com',
    'copilot-telemetry-service.githubusercontent.com',
    'copilot-telemetry.githubusercontent.com',
    'copilot-workspace.githubnext.com',
    'copilotprodattachments.blob.core.windows.net',
    'daily-cloudcode-pa.googleapis.com',
    'notebooklm-pa.googleapis.com',
    'notebooklm.googleapis.com',
    'o33249.ingest.sentry.io',
    'openaiapi-site.azureedge.net',
    'openaicom-api-bdcpf8c6d2e9atf6.z01.azurefd.net',
    'openaicom.imgix.net',
    'openaicomproductionae4b.blob.core.windows.net',
    'production-openaicom-storage.azureedge.net',
    'servd-anthropic-website.b-cdn.net',
    'webchannel-alkalimakersuite-pa.clients6.google.com',
    'agentclientprotocol.com',
    'ai.studio',
    'aicode.googleapis.com',
    'aida.googleapis.com',
    'aisandbox-pa.googleapis.com',
    'antigravity-unleash.goog',
    'antigravity.google',
    'anythingllm.com',
    'arena.ai',
    'bard.google.com',
    'cerebras.ai',
    'chat.com',
    'chatgpt.livekit.cloud',
    'chutes.ai',
    'cici.com',
    'ciciai.com',
    'ciciaicdn.com',
    'clau.de',
    'claudemcpclient.com',
    'claudeusercontent.com',
    'clawhub.ai',
    'clipdrop.co',
    'codeium.com',
    'codeiumdata.com',
    'coderabbit.ai',
    'coderabbit.gallery.vsassets.io',
    'cohere.ai',
    'cohere.com',
    'comfy.org',
    'comfyci.org',
    'comfyregistry.org',
    'copilot.microsoft.com',
    'coze.com',
    'crewai.com',
    'crixet.com',
    'cursor-cdn.com',
    'cursor.com',
    'cursor.sh',
    'cursorapi.com',
    'deepmind.com',
    'deepmind.google',
    'devin.ai',
    'diabrowser.com',
    'diabrowser.engineering',
    'dify.ai',
    'dola.com',
    'duck.ai',
    'elevenlabs.com',
    'elevenlabs.io',
    'envato-static.com',
    'envato.com',
    'envatousercontent.com',
    'gateway.ai.cloudflare.com',
    'geller-pa.googleapis.com',
    'gemini.google',
    'gemini.gstatic.com',
    'generativeai.google',
    'githubcopilot.com',
    'groq.com',
    'h2o.ai',
    'hf.co',
    'hf.space',
    'host.livekit.cloud',
    'huggingface.co',
    'jasper.ai',
    'jules.google',
    'jules.google.com',
    'kiro.dev',
    'labs.google',
    'labs.google.com',
    'langchain.com',
    'liveperson.net',
    'lmstudio.ai',
    'lovart.ai',
    'lpsnmedia.net',
    'makersuite.google.com',
    'manus.im',
    'manuscdn.com',
    'marscode.com',
    'meta.ai',
    'midjourney.com',
    'minimax.io',
    'mistral.ai',
    'mozilla.ai',
    'notebooklm.google',
    'notebooklm.google.com',
    'ollama.com',
    'opal.google',
    'opal.google.com',
    'openai.com.cdn.cloudflare.net',
    'openart.ai',
    'openclaw.ai',
    'openrouter.ai',
    'openspec.dev',
    'oystermercury.top',
    'plannotator.ai',
    'poe.com',
    'poecdn.net',
    'sora.com',
    'spicywriter.com',
    'stitch.withgoogle.com',
    'tapnow.ai',
    'themeforest.net',
    'trae.ai',
    'turn.livekit.cloud',
    'windsurf.build',
    'windsurf.com',
    'youmind.ai',
    'youmind.com',
    'youmind.site'
  ] },
  { name: "GitHub Copilot", domains: [
    'api.github.com',
    'api.individual.githubcopilot.com'
  ] },
  { name: "Gemini", domains: [
    'aistudio.google.com',
    'alkalimakersuite-pa.clients6.google.com',
    'gemini.google.com',
    'generativelanguage.googleapis.com',
    'proactivebackend-pa.googleapis.com',
    'robinfrontend-pa.googleapis.com'
  ] },
  { name: "Grok (xAI)", domains: [
    'api.x.com',
    'grok.x.com',
    'grok.com',
    'x.ai'
  ] },
  { name: "OpenAI", domains: [
    'chatgpt.com',
    'oaistatic.com',
    'oaiusercontent.com',
    'openai.com'
  ] },
  { name: "Perplexity", domains: [
    'ppl-ai-file-upload.s3.amazonaws.com',
    'pplx-res.cloudinary.com',
    'perplexity.ai',
    'perplexity.com',
    'pplx.ai'
  ] },
  { name: "Реклама и трекеры", domains: [
  ] },
  { name: "Adult content (18+)", domains: [
  ] },
  { name: "Заблокировано в РФ", domains: [
  ] },
  { name: "Российские сервисы", domains: [
    'gosuslugi.ru',
    'nalog.ru',
    'nalog.gov.ru',
    'cbr.ru',
    'pfr.gov.ru',
    'sfr.gov.ru',
    'mos.ru',
    'data.gov.ru',
    'pravo.gov.ru',
    'sberbank.ru',
    'sber.ru',
    'sberbank.com',
    'sbrf.ru',
    'sberprime.ru',
    'sberbankinsurance.ru',
    'sberdevices.ru',
    'sbermegamarket.ru',
    'vtb.ru',
    'vtbbank.com',
    'vtbbroker.ru',
    'tinkoff.ru',
    'tcsbank.ru',
    'tinkoffacademy.ru',
    'alfabank.ru',
    'alfa-bank.ru',
    'alfaforex.ru',
    'raiffeisen.ru',
    'raiffeisenbank.ru',
    'psbank.ru',
    'rshb.ru',
    'rosbank.ru',
    'otpbank.ru',
    'gazprombank.ru',
    'gpb.ru',
    'mtsbank.ru',
    'mts-bank.ru',
    'sovcombank.ru',
    'otkritie.ru',
    'open.ru',
    'mts.ru',
    'beeline.ru',
    'megafon.ru',
    'tele2.ru',
    'rt.ru',
    'rostelecom.ru',
    'yota.ru',
    'ozon.ru',
    'ozby.com',
    'wildberries.ru',
    'wbstatic.net',
    'wb.ru',
    'aliexpress.ru',
    'megamarket.ru',
    'yandex.ru',
    'yandex.net',
    'yandex.com',
    'ya.ru',
    'yastatic.net',
    'yandex-team.ru',
    'kinopoisk.ru',
    'kinopoisk.tv',
    'go.yandex',
    'eda.yandex',
    'dzen.ru',
    'vk.com',
    'vk.ru',
    'vk.me',
    'vkontakte.ru',
    'vkontakte.com',
    'userapi.com',
    'vkuseraudio.net',
    'vkuservideo.net',
    'vkplay.ru',
    'mail.ru',
    'ok.ru',
    'odnoklassniki.ru',
    'my.games',
    'avito.ru',
    'cian.ru',
    'hh.ru',
    'drom.ru',
    'auto.ru',
    'dostavista.ru',
    'delivery-club.ru',
    'rutube.ru',
    'ivi.ru',
    'okko.tv',
    'premier.one',
    'start.ru',
    'kion.ru',
    'wink.ru',
    'more.tv',
    'gismeteo.ru',
    '2gis.ru',
    '2gis.com',
    'ru',
    'su',
    'ru.com',
    'xn--p1ai',
    'xn--p1acf',
    'xn--80adxhks',
    'tatar',
    'xn--d1acj3b',
    'xn--80asehdb',
    'xn--80aswg',
    'xn--c1avg'
  ] },
  { name: "Akamai", domains: [
    'accdn.com.cn',
    'ak1.net',
    'aka-ai.com',
    'aka-ai.net',
    'akacrypto.net',
    'akadeem.net',
    'akadns.com',
    'akadns.net',
    'akadns6.net',
    'akadns88.net',
    'akadns99.net',
    'akaeai.com',
    'akafms.net',
    'akagtm.org',
    'akahost.net',
    'akaint.net',
    'akam.net',
    'akamaa.com',
    'akamah.com',
    'akamai-access.com',
    'akamai-access.net',
    'akamai-cdn.com',
    'akamai-platform-internal.net',
    'akamai-platform-staging.com',
    'akamai-platform.net',
    'akamai-regression.net',
    'akamai-staging.net',
    'akamai-sucks.net',
    'akamai-thailand.com',
    'akamai-thailand.net',
    'akamai-trials.com',
    'akamai.co.kr',
    'akamai.com',
    'akamai.net',
    'akamaiedge.net',
    'akamaientrypoint.net',
    'akamaietpcnctest.com',
    'akamaietpcompromisedcnctest.com',
    'akamaietpcompromisedmalwaretest.com',
    'akamaietpmalwaretest.com',
    'akamaietpphishingtest.com',
    'akamaihd-staging.net',
    'akamaihd.com',
    'akamaihd.net',
    'akamaimagicmath.net',
    'akamainewzealand.com',
    'akamaiphillipines.com',
    'akamaiphillipines.net',
    'akamaisingapore.net',
    'akamaistream.net',
    'akamaitech.com',
    'akamaitech.net',
    'akamaitechnologies.com',
    'akamaitechnologies.net',
    'akamaized-staging.net',
    'akamaized.net',
    'akamaizercentral.com',
    'akamak.com',
    'akamam.com',
    'akamci.com',
    'akami.com',
    'akami.net',
    'akamii.com',
    'akamqi.com',
    'akastream.com',
    'akastream.net',
    'akatns.net',
    'akcdn.com.cn',
    'akstat.io',
    'aptdn.net',
    'edgekey.net',
    'edgekey88.net',
    'edgesuite.net',
    'iamakamai.com',
    'iamakamai.net',
    'janrain.biz',
    'janrainservices.com',
    'skycdn.com.cn',
    'soasta-dswb.com',
    'srtcdn.net',
    'tl88.net'
  ] },
  { name: "Apple", domains: [
  ] },
  { name: "Amazon AWS", domains: [
    'aws',
    'a2z.org.cn',
    'acmvalidations.com',
    'acmvalidationsaws.com',
    'aesworkshops.com',
    'amazonaws-china.com',
    'amazonaws.biz',
    'amazonaws.cn',
    'amazonaws.co.uk',
    'amazonaws.com',
    'amazonaws.com.cn',
    'amazonaws.info',
    'amazonaws.net',
    'amazonaws.org',
    'amazonaws.tv',
    'amazoncognito.com',
    'amazonses.com',
    'amazonwebservices.cn',
    'amazonwebservices.com.cn',
    'amazonworkdocs.cn',
    'amazonworkdocs.com',
    'amazonworkdocs.com.cn',
    'amplifyapp.com',
    'amplifyframework.com',
    'amzndns-cn.biz',
    'amzndns-cn.cn',
    'amzndns-cn.com',
    'amzndns-cn.net',
    'amzndns.co.uk',
    'amzndns.com',
    'amzndns.net',
    'amzndns.org',
    'asfiovnxocqpcry.com.cn',
    'aws-border.cn',
    'aws-icp-domain-manager.cn',
    'aws-iot-hackathon.com',
    'aws.com',
    'aws.dev',
    'awsapprunner.com',
    'awsapps.cn',
    'awsapps.com',
    'awsapps.com.cn',
    'awsautopilot.com',
    'awsautoscaling.com',
    'awsbraket.com',
    'awscommandlineinterface.com',
    'awsedstart.com',
    'awseducate.com',
    'awseducate.net',
    'awseducate.org',
    'awsglobalaccelerator.com',
    'awsloft-johannesburg.com',
    'awsloft-stockholm.com',
    'awssecworkshops.com',
    'awsstatic.cn',
    'awsstatic.com',
    'awsthinkbox.com',
    'awstrack.me',
    'awswaf.com',
    'cdkworkshop.com',
    'cloudfront-cn.net',
    'cloudfront-test.cn',
    'cloudfront.cn',
    'cloudfront.com',
    'cloudfront.net',
    'containersonaws.com',
    'elasticbeanstalk.com',
    'nwcdcloud.cn',
    'nwcdcloud.com.cn',
    'nwcddns.cn',
    'nwcdinfosec.cn',
    'route53.cn',
    'sagemaker.com.cn',
    'thinkboxsoftware.com'
  ] },
  { name: "Binance", domains: [
    'appsflayer.com',
    'binance.cc',
    'binance.charity',
    'binance.cloud',
    'binance.co',
    'binance.com',
    'binance.info',
    'binance.me',
    'binance.net',
    'binance.org',
    'binance.us',
    'binance.vision',
    'binanceapi.com',
    'binancecnt.com',
    'binanceru.net',
    'binancezh.be',
    'binancezh.biz',
    'binancezh.cc',
    'binancezh.co',
    'binancezh.com',
    'binancezh.info',
    'binancezh.ink',
    'binancezh.kim',
    'binancezh.link',
    'binancezh.live',
    'binancezh.mobi',
    'binancezh.net',
    'binancezh.pro',
    'binancezh.sh',
    'binancezh.top',
    'bnbstatic.com',
    'bntrace.com',
    'bsappapi.com',
    'nftstatic.com',
    'saasexch.cc',
    'saasexch.co',
    'saasexch.com',
    'saasexch.io'
  ] },
  { name: "Cloudflare", domains: [
    'argotunnel.com',
    'browser.run',
    'cf-china.info',
    'cf-ipfs.com',
    'cf-ns.com',
    'cf-ns.net',
    'cf-ns.site',
    'cf-ns.tech',
    'cfargotunnel.com',
    'cfdata.org',
    'cfl.re',
    'cftest5.cn',
    'cftest6.cn',
    'cftest7.com',
    'cftest8.com',
    'cloudflare-cn.com',
    'cloudflare-dns.com',
    'cloudflare-ech.com',
    'cloudflare-esni.com',
    'cloudflare-gateway.com',
    'cloudflare-ipfs.com',
    'cloudflare-quic.com',
    'cloudflare-terms-of-service-abuse.com',
    'cloudflare.com',
    'cloudflare.dev',
    'cloudflare.net',
    'cloudflare.tv',
    'cloudflareaccess.com',
    'cloudflareanycast.net',
    'cloudflareapps.com',
    'cloudflarebolt.com',
    'cloudflarebrowser.com',
    'cloudflarechallenge.com',
    'cloudflarechina.cn',
    'cloudflareclient.com',
    'cloudflarecn.net',
    'cloudflarecp.com',
    'cloudflareglobal.net',
    'cloudflareinsights-cn.com',
    'cloudflareinsights.com',
    'cloudflareok.com',
    'cloudflarepartners.com',
    'cloudflareperf.com',
    'cloudflareportal.com',
    'cloudflarepreview.com',
    'cloudflareprod.com',
    'cloudflareregistrar.com',
    'cloudflareresearch.com',
    'cloudflareresolve.com',
    'cloudflaressl.com',
    'cloudflarestaging.com',
    'cloudflarestatus.com',
    'cloudflarestorage.com',
    'cloudflarestoragegw.com',
    'cloudflarestream.com',
    'cloudflaresupport.com',
    'cloudflaretest.com',
    'cloudflarewarp.com',
    'cloudflareworkers.com',
    'encryptedsni.com',
    'every1dns.net',
    'foundationdns.com',
    'foundationdns.net',
    'foundationdns.org',
    'imagedelivery.net',
    'isbgpsafeyet.com',
    'one.one.one',
    'pacloudflare.com',
    'pages.dev',
    'r2.dev',
    'trycloudflare.com',
    'videodelivery.net',
    'warp.plus',
    'workers.dev'
  ] },
  { name: "Cloudflare IPs", domains: [
  ] },
  { name: "Google Play", domains: [
    'redirector.c.play.google.com',
    'googleplay.com',
    'play-fe.googleapis.com',
    'play-games.googleusercontent.com',
    'play-lh.googleusercontent.com',
    'play.google.com',
    'play.googleapis.com',
    'xn--ngstr-lra8j.com'
  ] },
  { name: "Microsoft", domains: [
  ] },
  { name: "NVIDIA", domains: [
    'cn.download.nvidia.com',
    'nvidia.custhelp.com',
    'nvidia.tt.omtrdc.net',
    'geforce.cn',
    'geforce.co.kr',
    'geforce.co.uk',
    'geforce.com',
    'geforce.com.tw',
    'gputechconf.cn',
    'gputechconf.co.kr',
    'gputechconf.com',
    'gputechconf.com.au',
    'gputechconf.com.tw',
    'gputechconf.eu',
    'gputechconf.in',
    'gputechconf.jp',
    'nvidia.asia',
    'nvidia.at',
    'nvidia.be',
    'nvidia.ch',
    'nvidia.cn',
    'nvidia.co.at',
    'nvidia.co.in',
    'nvidia.co.jp',
    'nvidia.co.kr',
    'nvidia.co.uk',
    'nvidia.com',
    'nvidia.com.au',
    'nvidia.com.br',
    'nvidia.com.mx',
    'nvidia.com.pe',
    'nvidia.com.pl',
    'nvidia.com.tr',
    'nvidia.com.tw',
    'nvidia.com.ua',
    'nvidia.com.ve',
    'nvidia.cz',
    'nvidia.de',
    'nvidia.dk',
    'nvidia.es',
    'nvidia.eu',
    'nvidia.fi',
    'nvidia.fr',
    'nvidia.in',
    'nvidia.it',
    'nvidia.jp',
    'nvidia.lu',
    'nvidia.mx',
    'nvidia.nl',
    'nvidia.no',
    'nvidia.pl',
    'nvidia.ro',
    'nvidia.ru',
    'nvidia.se',
    'nvidia.tw',
    'nvidiaforhp.com',
    'nvidiagrid.net',
    'shotwithgeforce.com',
    'tegrazone.co',
    'tegrazone.co.kr',
    'tegrazone.com',
    'tegrazone.jp',
    'tegrazone.kr'
  ] },
  { name: "Samsung", domains: [
    'samsung',
    'samsung.com',
    'galaxyappstore.com',
    'galaxymobile.jp',
    'game-platform.net',
    'knoxemm.com',
    'ospserver.net',
    'samsungads.com',
    'samsungapps.com',
    'samsungcloud.com',
    'samsungconsent.com',
    'samsungdm.com',
    'samsungeshop.com.cn',
    'samsunggalaxyfriends.com',
    'samsunghealth.com',
    'samsungiotcloud.com',
    'samsungiots.com',
    'samsungknox.com',
    'samsungosp.com',
    'samsungqbe.com',
    'samsungrs.com',
    'smartthings.com'
  ] },
  { name: "Adobe", domains: [
    'adobeereg.com',
    'crl.versign.net',
    'ood.opsource.net',
    'practivate.adobe',
    'practivate.adobe.ipp',
    'practivate.adobe.newoa',
    'practivate.adobe.ntp',
    '10xfotolia.com',
    '2o7.net',
    'acrobat.com',
    'adbecrsl.com',
    'adobe-aemassets-value.com',
    'adobe-audience-finder.com',
    'adobe-video-partner-finder.com',
    'adobe.com',
    'adobe.io',
    'adobe.ly',
    'adobeaemcloud.com',
    'adobeaemcloud.net',
    'adobeawards.com',
    'adobecc.com',
    'adobecce.com',
    'adobeccstatic.com',
    'adobecontent.io',
    'adobecreativityawards.com',
    'adobedc.cn',
    'adobedc.net',
    'adobedemo.com',
    'adobedtm.com',
    'adobeexchange.com',
    'adobeexperienceawards.com',
    'adobegov.com',
    'adobehiddentreasures.com',
    'adobejanus.com',
    'adobeku.com',
    'adobelanding.com',
    'adobelogin.com',
    'adobeoobe.com',
    'adobeplatinumclub.com',
    'adobeprojectm.com',
    'adobesc.com',
    'adobesign.com',
    'adobesigncdn.com',
    'adobespark.com',
    'adobess.com',
    'adobestats.io',
    'adobestock.com',
    'adobetag.com',
    'adobetarget.com',
    'adobetcstrialdvd.com',
    'adobetechcomm.com',
    'adobetechcommcallback.com',
    'adobetechcommdemo.com',
    'adobexdplatform.com',
    'advertising.adobe.com',
    'assetsadobe.com',
    'authorxml.com',
    'behance.net',
    'bluefootcms.com',
    'businesscatalyst.com',
    'ccnsite.com',
    'ccpsx.com',
    'compresspdf.new',
    'cotolia.com',
    'creativecloud.com',
    'creativesdk.com',
    'demdex.net',
    'developria.com',
    'dollarfotoclub.com',
    'dollarphotoclub.com',
    'dollarphotosclub.com',
    'douwriteright.com',
    'echocdn.com',
    'echosign.com',
    'edgefonts.net',
    'enablementadobe.com',
    'ffotolia.com',
    'fiotolia.com',
    'foftolia.com',
    'fonolia.com',
    'fotiolia.com',
    'fotoiia.com',
    'fotolia-noticias.com',
    'fotolia.cc',
    'fotolia.com',
    'fotolia.tv',
    'fotolja.com',
    'fptolia.com',
    'ftcdn.net',
    'gfotolia.com',
    'gostorego.com',
    'imagineecommerce.com',
    'macromedia.com',
    'mageconf.com',
    'mageconf.com.ua',
    'magento.com',
    'magento.net',
    'magentocommerce.com',
    'magentoliveconference.com',
    'magentomobile.com',
    'marketing-cloud.com',
    'marketing-nirvana.com',
    'marketo.co.uk',
    'marketo.com',
    'marketo.net',
    'marketo.tv',
    'marketodesigner.com',
    'marketolive.com',
    'mktdns.com',
    'mkto-c0100.com',
    'mktorest.com',
    'mktroute.com',
    'mobilemarketo.com',
    'motolia.com',
    'omniture.com',
    'omtrdc.net',
    'pdf.new',
    'photolia.net',
    'photoshop.com',
    'placesdocs.com',
    'revenue-performance-management.com',
    's2stagehance.com',
    'scene7.com',
    'sign.new',
    'sundanceignite2016.com',
    'tenbyfotolia.com',
    'toutapp.com',
    'tubemogul.com',
    'typekit.com',
    'typekit.net',
    'votolia.com',
    'worldsecureemail.com',
    'worldsecuresystems.com'
  ] },
  { name: "Atlassian", domains: [
    'atl-paas.net',
    'atlassian.com',
    'ss-inf.net',
    'atlassian.net',
    'jira.com',
    'bitbucket.org',
    'atlassian-dev.net',
    'confluence.com'
  ] },
  { name: "Canva", domains: [
    'affinity-beta.s3.amazonaws.com',
    'affinity-lessons.s3.amazonaws.com',
    'affinity.api.serifservices.com',
    'affinity.studio',
    'canva.com',
    'canvastatus.com'
  ] },
  { name: "Dev tools", domains: [
    'applicationinsights.io',
    'awg.go',
    'bootstrap.pypa.io',
    'bun.sh',
    'cdn.jsdelivr.net',
    'context7.com',
    'coolors.co',
    'crates.io',
    'cursor-cdn.com',
    'cursor.com',
    'cursor.sh',
    'cursorapi.com',
    'deno.land',
    'exp-tas.com',
    'gcr.io',
    'golang.org',
    'gradle.org',
    'hashicorp.com',
    'helm.sh',
    'k8s.io',
    'kubernetes.io',
    'maven.org',
    'mcr.microsoft.com',
    'mui.com',
    'nuget.org',
    'packagist.org',
    'pkg.go.dev',
    'pypi.org',
    'pythonhosted.org',
    'quay.io',
    'react.com',
    'registry.terraform.io',
    'rubygems.global.ssl.fastly.net',
    'rubygems.org',
    'storage.googleapis.com',
    'suno.com',
    'wakatime.com',
    'yarnpkg.com'
  ] },
  { name: "Docker", domains: [
    'docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com',
    'docker-pinata-support.s3.amazonaws.com',
    'compose-spec.io',
    'docker.com',
    'docker.io',
    'dockerstatic.com'
  ] },
  { name: "Figma", domains: [
    'figma.com'
  ] },
  { name: "GitHub", domains: [
    'copilot-telemetry-service.githubusercontent.com',
    'copilot-telemetry.githubusercontent.com',
    'copilotprodattachments.blob.core.windows.net',
    'github-api.arkoselabs.com',
    'github-cloud.s3.amazonaws.com',
    'github-production-release-asset-2e65be.s3.amazonaws.com',
    'github-production-repository-file-5c1aeb.s3.amazonaws.com',
    'github-production-repository-image-32fea6.s3.amazonaws.com',
    'github-production-upload-manifest-file-7fdce7.s3.amazonaws.com',
    'github-production-user-asset-6210df.s3.amazonaws.com',
    'productionresultssa0.blob.core.windows.net',
    'productionresultssa1.blob.core.windows.net',
    'productionresultssa10.blob.core.windows.net',
    'productionresultssa11.blob.core.windows.net',
    'productionresultssa12.blob.core.windows.net',
    'productionresultssa13.blob.core.windows.net',
    'productionresultssa14.blob.core.windows.net',
    'productionresultssa15.blob.core.windows.net',
    'productionresultssa16.blob.core.windows.net',
    'productionresultssa17.blob.core.windows.net',
    'productionresultssa18.blob.core.windows.net',
    'productionresultssa19.blob.core.windows.net',
    'productionresultssa2.blob.core.windows.net',
    'productionresultssa3.blob.core.windows.net',
    'productionresultssa4.blob.core.windows.net',
    'productionresultssa5.blob.core.windows.net',
    'productionresultssa6.blob.core.windows.net',
    'productionresultssa7.blob.core.windows.net',
    'productionresultssa8.blob.core.windows.net',
    'productionresultssa9.blob.core.windows.net',
    'atom.io',
    'collector.github.com',
    'dependabot.com',
    'gh.io',
    'ghcr.io',
    'git.io',
    'github.ai',
    'github.blog',
    'github.com',
    'github.community',
    'github.dev',
    'github.io',
    'githubapp.com',
    'githubassets.com',
    'githubcopilot.com',
    'githubhackathon.com',
    'githubnext.com',
    'githubpreview.dev',
    'githubstatus.com',
    'githubuniverse.com',
    'githubusercontent.com',
    'myoctocat.com',
    'npm.community',
    'npmjs.com',
    'npmjs.org',
    'octocaptcha.com',
    'opensource.guide',
    'repo.new',
    'thegithubshop.com'
  ] },
  { name: "GitLab", domains: [
    'gitlab-assets.oss-cn-hongkong.aliyuncs.com',
    'gitlab-static.net',
    'gitlab.com',
    'gitlab.io',
    'gitlab.net'
  ] },
  { name: "IP checkers", domains: [
    'ipleak.net',
    'dnsleaktest.com',
    'dnsleak.com',
    'browserleaks.com',
    'whoer.net',
    'whoerip.com',
    '2ip.ru',
    '2ip.io',
    'ipinfo.io',
    'ipapi.is',
    'ipapi.co',
    'ipapi.com',
    'whatismyipaddress.com',
    'whatismyip.com',
    'whatismyip.net',
    'whatismyip.org',
    'myip.com',
    'myip.ms',
    'showmyip.com',
    'myexternalip.com',
    'ip.me',
    'ipcheck.ing',
    'ip-api.com',
    'ipify.org',
    'ident.me',
    'ifconfig.me',
    'ifconfig.co',
    'icanhazip.com',
    'ipecho.net',
    'wtfismyip.com',
    'iplocation.net',
    'iplocation.io',
    'geojs.io',
    'ipwhois.io',
    'ipgeolocation.io',
    'ipstack.com',
    'ipdata.co',
    'abstractapi.com',
    'ipregistry.co',
    'ipinfoip.com',
    'ipinfoip.net',
    'ipinfoip.org',
    'ip-tracker.org',
    'ip-tracing.com',
    'ip-tracer.org',
    'ip-checker.info',
    'ipcheck.org',
    'ipfingerprints.com',
    'ip-adress.com',
    'ip-adress.eu',
    'ip-adress.my',
    'ipaddress.com',
    'ipaddress.my',
    'check-host.net',
    'examineip.com',
    'mullvad.net',
    'surfshark.com',
    'nordvpn.com',
    'expressvpn.com',
    'vpnmentor.com',
    'torguard.net',
    'vpntester.org',
    'secureblitz.com',
    'todetect.net',
    'pixelscan.net',
    'ipx.ac',
    'webbrowsertools.com',
    'xvpn.io',
    'scrapfly.io',
    'iproyal.com',
    'enable-security.com',
    'iplocator.net',
    'iptrackeronline.com',
    'ip2location.com',
    'ip2location.io',
    'ip2whois.com',
    'ipqualityscore.com',
    'ip-lookup.net',
    'ip-lookup.io',
    'ip-lookup.org',
    'ip-whois.org',
    'ip-whois.net',
    'ip-whois.io',
    'ip-geolocation.org',
    'ip-geolocation.io',
    'ip-geolocation-api.com',
    'ip-geolocation-api.io',
    'ip-geolocation-api.org',
    'stun.l.google.com',
    'stun1.l.google.com',
    'stun2.l.google.com',
    'stun3.l.google.com',
    'stun4.l.google.com',
    'stun.ekiga.net',
    'stun.ideasip.com',
    'stun.stunprotocol.org',
    'stun.voiparound.com',
    'stun.voipbuster.com',
    'stun.voipstunt.com',
    'stun.voxgratia.org',
    'stun.schlund.de',
    'stun.rixtelecom.se',
    'stun.services.mozilla.com',
    'stun.qq.com',
    'stun.miwifi.com',
    'turn.anyfirewall.com',
    'turn.bistri.com',
    'turn.num.viagenie.ca',
    'freeturn.net',
    'openrelayproject.org',
    'turnix.io',
    'fastturn.net'
  ] },
  { name: "JetBrains", domains: [
    'cdn.jetbrains.com',
    'datalore.io',
    'download-cdn.jetbrains.com.cn',
    'intellij.com',
    'intellij.net',
    'intellij.org',
    'jb.gg',
    'jetbrains.cloud',
    'jetbrains.com',
    'jetbrains.net',
    'jetbrains.space',
    'jetbrains.team',
    'kotlinlang.org',
    'youtrack.cloud'
  ] },
  { name: "LinkedIn", domains: [
    'licdn.com',
    'linkedin.com'
  ] },
  { name: "Notion", domains: [
    'notion-static.com',
    'notion.com',
    'notion.new',
    'notion.site',
    'notion.so',
    'notionusercontent.com'
  ] },
  { name: "npm", domains: [
    'npm.community',
    'npmjs.com',
    'npmjs.org'
  ] },
  { name: "Slack", domains: [
    'slack-core.com',
    'slack-edge.com',
    'slack-files.com',
    'slack-imgs.com',
    'slack-msgs.com',
    'slack-redir.net',
    'slack.com',
    'slackb.com',
    'slackcertified.com',
    'slackdemo.com',
    'slackhq.com'
  ] },
  { name: "Vercel", domains: [
    'ai-sdk.dev',
    'err.sh',
    'hyper.is',
    'nextjs.org',
    'now.sh',
    'skills.sh',
    'static.fun',
    'title.sh',
    'turborepo.org',
    'vercel-dns.com',
    'vercel-status.com',
    'vercel.app',
    'vercel.blog',
    'vercel.com',
    'vercel.dev',
    'vercel.events',
    'vercel.live',
    'vercel.pub',
    'vercel.sh',
    'vercel.store',
    'zeit-world.co.uk',
    'zeit-world.com',
    'zeit-world.net',
    'zeit-world.org',
    'zeit.co',
    'zeit.sh',
    'zeitworld.com'
  ] },
  { name: "Zoom", domains: [
    'zoom.com',
    'zoom.com.cn',
    'zoom.us'
  ] },
  { name: "Blizzard", domains: [
    'blizzard.nefficient.co.kr',
    'blizzcon-a.akamaihd.net',
    'blzddist1-a.akamaihd.net',
    'blzddistkr1-a.akamaihd.net',
    'blzmedia-a.akamaihd.net',
    'blznav.akamaized.net',
    'bnetcmsus-a.akamaihd.net',
    'bnetproduct-a.akamaihd.net',
    'bnetshopus.akamaized.net',
    'battle.net',
    'blizzard.com',
    'blizzardgearstore.com',
    'blz-contentstack.com',
    'diablo3.com',
    'diabloimmortal.com',
    'firesidegatherings.com',
    'heroesofthestorm.com',
    'playhearthstone.com',
    'playoverwatch.com',
    'playwarcraft3.com',
    'starcraft.com',
    'starcraft2.com',
    'worldofwarcraft.com'
  ] },
  { name: "Все игры", domains: [
  ] },
  { name: "Epic Games", domains: [
    '3lateral.com',
    'artstation.com',
    'battlebreakers.com',
    'capturingreality.com',
    'cubicmotion.com',
    'eac-cdn.com',
    'easy.ac',
    'easyanticheat.net',
    'egdownload.fastly-edge.com',
    'epicgames.com',
    'epicgames.dev',
    'epicgamescdn.com',
    'fab.com',
    'fortnite-vod.akamaized.net',
    'fortnite.com',
    'hyprsense.com',
    'paragon.com',
    'playparagon.com',
    'quixel.com',
    'quixel.se',
    'radgametools.com',
    'realityscan.com',
    'roborecall.com',
    'shadowcomplex.com',
    'sketchfab.com',
    'spyjinx.com',
    'twinmotion.com',
    'unrealengine.com',
    'unrealtournament.com'
  ] },
  { name: "Nintendo", domains: [
    'd4c.nintendo.net',
    'dragons.nintendo.net',
    'eshop.nintendo.net',
    'srv.nintendo.net'
  ] },
  { name: "Oculus / Quest", domains: [
    'binoculus.com',
    'buyoculus.com',
    'ocul.us',
    'oculus-china.com',
    'oculus.com',
    'oculus2014.com',
    'oculus3d.com',
    'oculusblog.com',
    'oculusbrand.com',
    'oculuscasino.net',
    'oculuscdn.com',
    'oculusconnect.com',
    'oculusdiving.com',
    'oculusforbusiness.com',
    'oculusrift.com',
    'oculusvr.com',
    'powersunitedvr.com'
  ] },
  { name: "PlayStation", domains: [
    'playstation',
    'playstation.com',
    'playstation.net',
    'sonyentertainmentnetwork.com'
  ] },
  { name: "Roblox", domains: [
    'rbxcdn.com',
    'roblox.com'
  ] },
  { name: "Steam", domains: [
    'a4e8s8k3.map2.ssl.hwcdn.net',
    'alibaba.cdn.steampipe.steamcontent.com',
    'f3b7q2p3.ssl.hwcdn.net',
    'lv.queniujq.cn',
    'steambroadcast.akamaized.net',
    'steamcdn-a.akamaihd.net',
    'steamcloudsweden.blob.core.windows.net',
    'steamcommunity-a.akamaihd.net',
    'steamcommunity-a.akamaihd.net.edgesuite.net',
    'steammobile.akamaized.net',
    'steampipe-kr.akamaized.net',
    'steampipe-partner.akamaized.net',
    'steampipe.akamaized.net',
    'steamstore-a.akamaihd.net',
    'steamusercontent-a.akamaihd.net',
    'steamuserimages-a.akamaihd.net',
    'steamvideo-a.akamaihd.net',
    'xz.pphimalayanrt.com',
    'client-update.queniuqe.com',
    'csgo.wmsj.cn',
    'dl.steam.clngaa.com',
    'dota2.wmsj.cn',
    'edge.steam-dns.top.comcast.net',
    'gstore.val.manlaxy.com',
    'playartifact.com',
    's.team',
    'st.dl.bscstorage.net',
    'st.dl.eccdnx.com',
    'st.dl.pinyuncloud.com',
    'steam-api.com',
    'steam-chat.com',
    'steam.apac.qtlglb.com',
    'steam.cdn.on.net',
    'steam.cdn.orcon.net.nz',
    'steam.cdn.slingshot.co.nz',
    'steam.cdn.webra.ru',
    'steam.eca.qtlglb.com',
    'steam.naeu.qtlglb.com',
    'steam.ru.qtlglb.com',
    'steam.tv',
    'steamchina.com',
    'steamcommunity.com',
    'steamcontent.com',
    'steamdeck.com',
    'steamgames.com',
    'steampowered.com',
    'steampowered.com.8686c.com',
    'steamserver.net',
    'steamstatic.com',
    'steamstatic.com.8686c.com',
    'steamusercontent.com',
    'underlords.com',
    'valvesoftware.com',
    'wmsjsteam.com'
  ] },
  { name: "Ubisoft", domains: [
    'ubi.com',
    'ubisoft.com',
    'ubisoftconnect.com',
    'uplay.com',
    'ubisoft-uplay-savegames.s3.amazonaws.com',
    'ubisoft-orbit-savegames.s3.amazonaws.com',
    'ubistatic1-a.akamaihd.net',
    'ubisoft.siteintercept.qualtrics.com'
  ] },
  { name: "Xbox", domains: [
    'flightsimulator.azureedge.net',
    'prodforza.blob.core.windows.net',
    'xbox',
    'asobostudio.com',
    'beth.games',
    'bethesda.net',
    'bethesdagamestudios.com',
    'bethsoft.com',
    'callersbane.com',
    'doom.com',
    'elderscrolls.com',
    'flightsimulator.com',
    'forza.net',
    'forzamotorsport.net',
    'forzaracingchampionship.com',
    'forzarc.com',
    'gamepass.com',
    'minecraft-services.net',
    'minecraft.net',
    'minecraftservices.com',
    'minecraftshop.com',
    'mojang.com',
    'orithegame.com',
    'renovacionxboxlive.com',
    'tellmewhygame.com',
    'xbox.co',
    'xbox.com',
    'xbox.eu',
    'xbox.org',
    'xbox360.co',
    'xbox360.com',
    'xbox360.eu',
    'xbox360.org',
    'xboxab.com',
    'xboxgamepass.com',
    'xboxgamestudios.com',
    'xboxlive.cn',
    'xboxlive.com',
    'xboxone.co',
    'xboxone.com',
    'xboxone.eu',
    'xboxplayanywhere.com',
    'xboxservices.com',
    'xboxstudios.com',
    'xbx.lv'
  ] },
  { name: "BBC", domains: [
    'aod-pod-uk-live.akamaized.net',
    'as-dash-uk-live.akamaized.net',
    'as-hls-uk-live.akamaized.net',
    've-dash-uk-live.akamaized.net',
    've-uhd-push-uk-live.akamaized.net',
    'vod-dash-uk-live.akamaized.net',
    'vod-dash-ww-live.akamaized.net',
    'vod-hls-uk-live.akamaized.net',
    'vod-sub-uk-live.akamaized.net',
    'vod-thumb-uk-live.akamaized.net',
    'vod-thumb-ww-live.akamaized.net',
    'vs-cmaf-push-uk-live.akamaized.net',
    'vs-cmaf-pushb-ww-live.akamaized.net',
    'vs-hls-push-uk-live.akamaized.net',
    'vs-hls-pushb-uk-live.akamaized.net',
    'bbc',
    'bbc-reporting-api.app',
    'bbc.co.uk',
    'bbc.com',
    'bbc.in',
    'bbc.mp-pxcdn.com',
    'bbc.net.uk',
    'bbcfmt.s.llnwi.net',
    'bbci.co.uk',
    'bbcmedia.co.uk',
    'bbcpersian.com',
    'bbcverticals.com',
    'bidi.net.uk'
  ] },
  { name: "Всё медиа", domains: [
  ] },
  { name: "Deezer", domains: [
    'deezer.com',
    'dzcdn.net'
  ] },
  { name: "HBO", domains: [
    'hbo',
    'beforeigners.com',
    'brightline.tv',
    'cinemax.com',
    'discomax.com',
    'elpionero.es',
    'forthethrone.com',
    'hbo-europe.com',
    'hbo.ba',
    'hbo.bg',
    'hbo.com',
    'hbo.com.c.footprint.net',
    'hbo.com.edgesuite.net',
    'hbo.cz',
    'hbo.eu',
    'hbo.hr',
    'hbo.hu',
    'hbo.map.fastly.net',
    'hbo.me',
    'hbo.mk',
    'hbo.pl',
    'hbo.ro',
    'hbo.rs',
    'hbo.sk',
    'hboaccess.com',
    'hboarchives.com',
    'hboasia.com',
    'hboenterprises.com',
    'hboespana.com',
    'hbogo.co.th',
    'hbogo.com',
    'hbogo.cz',
    'hbogo.eu',
    'hbogo.hu',
    'hbogo.sk',
    'hbogoasia.com',
    'hbogoasia.hk',
    'hbogoasia.id',
    'hbogoasia.my',
    'hbogoasia.ph',
    'hbogoasia.sg',
    'hbogoasia.tw',
    'hboinflight.com',
    'hbolacontent.net',
    'hbolaunchpad.com',
    'hbomailman.com',
    'hbomax-images.warnermediacdn.com',
    'hbomax.com',
    'hbomax.eu',
    'hbomaxcdn.com',
    'hbomaxdash.s.llnwi.net',
    'hbomediarelations.com',
    'hbonordic.com',
    'hbonordic.tv',
    'hbonow.com',
    'hboportugal.com',
    'hboprod.com',
    'hbospain.com',
    'hbotvsales.com',
    'homebox.com',
    'homeboxoffice.com',
    'max.com',
    'maxgo.com',
    'redbyhbo.com'
  ] },
  { name: "Hulu", domains: [
    'hulu.playback.edge.bamgrid.com',
    '112263.com',
    'callhulu.com',
    'findyourlimits.com',
    'freehulu.com',
    'hooloo.tv',
    'hoolu.com',
    'hoolu.tv',
    'hu1u.com',
    'huloo.cc',
    'huloo.tv',
    'hulu.com',
    'hulu.jp',
    'hulu.tv',
    'hulu.us',
    'huluaction.com',
    'huluad.com',
    'huluapp.com',
    'huluasks.com',
    'hulucall.com',
    'hulufree.com',
    'hulugans.com',
    'hulugermany.com',
    'hulugo.com',
    'huluim.com',
    'huluinstantmessenger.com',
    'huluitaly.com',
    'hulunet.com',
    'hulunetwork.com',
    'huluplus.com',
    'hulupremium.com',
    'hulupurchase.com',
    'huluqa.com',
    'hulurussia.com',
    'huluspain.com',
    'hulusports.com',
    'hulustream.com',
    'huluteam.com',
    'hulutv.com',
    'huluusa.com',
    'joinmaidez.com',
    'mushymush.tv',
    'myhulu.com',
    'originalhulu.com',
    'payhulu.com',
    'registerhulu.com',
    'thehulubraintrust.com',
    'wwwhuluplus.com'
  ] },
  { name: "Kino.pub", domains: [
    'ahc.ovh',
    'cdn-service.space',
    'cdn2cdn.com',
    'cdn2site.com',
    'gfw.ovh',
    'kino.pub',
    'kinopub.online',
    'kpdl.link',
    'mos-gorsud.co',
    'pushbr.com',
    'smarttvcdn.online'
  ] },
  { name: "Netflix", domains: [
    'fast.com',
    'netflix.com',
    'nflxext.com',
    'nflximg.net',
    'nflxvideo.net'
  ] },
  { name: "Prime Video", domains: [
    'd1v5ir2lpwr8os.cloudfront.net',
    'd22qjgkvxw22r6.cloudfront.net',
    'd25xi40x97liuc.cloudfront.net',
    'd27xxe7juh1us6.cloudfront.net',
    'dmqdd6hw24ucf.cloudfront.net',
    'images-eu.ssl-images-amazon.com',
    'images-fe.ssl-images-amazon.com',
    'images-na.ssl-images-amazon.com',
    'msh.amazon.co.uk',
    'static.siege-amazon.com',
    'aiv-cdn.net',
    'amazonprimevideo.cn',
    'amazonprimevideo.com.cn',
    'amazonprimevideos.com',
    'amazonvideo.cc',
    'amazonvideo.com',
    'prime-video.com',
    'primevideo.cc',
    'primevideo.com',
    'primevideo.info',
    'primevideo.org',
    'primevideo.tv',
    'prod.service.minerva.devices.a2z.com'
  ] },
  { name: "SoundCloud", domains: [
    'sndcdn.com',
    'soundcloud.cloud',
    'soundcloud.com'
  ] },
  { name: "Spotify", domains: [
    'adeventtracker.spotify.com',
    'adstudio-assets.scdn.co',
    'audio-ak-spotify-com.akamaized.net',
    'audio4-ak-spotify-com.akamaized.net',
    'bloodhound.spotify.com',
    'cdn-spotify-experiments.conductrics.com',
    'heads-ak-spotify-com.akamaized.net',
    'heads4-ak-spotify-com.akamaized.net',
    'spotify.com.edgesuite.net',
    'spotify.map.fastly.net',
    'spotify.map.fastlylb.net',
    'byspotify.com',
    'pscdn.co',
    'scdn.co',
    'spoti.fi',
    'spotify-everywhere.com',
    'spotify.com',
    'spotify.design',
    'spotify.link',
    'spotifycdn.com',
    'spotifycdn.net',
    'spotifycharts.com',
    'spotifycodes.com',
    'spotifyforbrands.com',
    'spotifyjobs.com',
    'tospotify.com'
  ] },
  { name: "Tidal", domains: [
    'tidal.com',
    'tidalhifi.com',
    'wimpmusic.com'
  ] },
  { name: "TMDB", domains: [
    'themoviedb.org',
    'tmdb.org',
    'tmdb-image-prod.b-cdn.net'
  ] },
  { name: "Torrents", domains: [
    '1337x.to',
    'booktracker.org',
    'booktracker.work',
    'eu.org',
    'filmitorrent.net',
    'freetp.org',
    'kinozal.me',
    'newstudio.tv',
    'nnmclub.to',
    'nnmstatic.win',
    'rustorka.com',
    'rutrc.org',
    'rutor.info',
    'rutor.is',
    'rutor.org',
    'rutracker.cc',
    'rutracker.net',
    'rutracker.org',
    'rutracker.ru',
    'rutracker.wiki',
    'rutrk.org',
    'stealth.si',
    't-ru.org',
    'thepiratebay.org',
    'torrent.by',
    'torrindex.net',
    'wstracker.online',
    'ysagin.top'
  ] },
  { name: "Twitch", domains: [
    'd1g1f25tn8m2e6.cloudfront.net',
    'd1m7jfoe9zdc1j.cloudfront.net',
    'd1mhjrowxxagfy.cloudfront.net',
    'd1ndex63qxojbr.cloudfront.net',
    'd1oca24q5dwo6d.cloudfront.net',
    'd1w2poirtb3as9.cloudfront.net',
    'd1xhnb4ptk05mw.cloudfront.net',
    'd1ymi26ma8va5x.cloudfront.net',
    'd2aba1wr3818hz.cloudfront.net',
    'd2dylwb3shzel1.cloudfront.net',
    'd2e2de1etea730.cloudfront.net',
    'd2nvs31859zcd8.cloudfront.net',
    'd2um2qdswy1tb0.cloudfront.net',
    'd2vjef5jvl6bfs.cloudfront.net',
    'd2xmjdvx03ij56.cloudfront.net',
    'd36nr0u3xmc4mm.cloudfront.net',
    'd3aqoihi2n8ty8.cloudfront.net',
    'd3c27h4odz752x.cloudfront.net',
    'd3vd9lfkzbru3h.cloudfront.net',
    'd6d4ismr40iw.cloudfront.net',
    'd6tizftlrpuof.cloudfront.net',
    'ddacn6pr5v0tl.cloudfront.net',
    'dgeft87wbj63p.cloudfront.net',
    'dqrpb9wgowsf5.cloudfront.net',
    'ds0h3roq6wcgc.cloudfront.net',
    'dykkng5hnh52u.cloudfront.net',
    'ext-twitch.tv',
    'jtvnw.net',
    'live-video.net',
    'ttvnw.net',
    'twitch.tv',
    'twitchcdn.net',
    'twitchcon.com',
    'twitchsvc.net'
  ] },
  { name: "Vimeo", domains: [
    'livestream.com',
    'vhx.tv',
    'vhxqa1.com',
    'vhxqa2.com',
    'vhxqa3.com',
    'vhxqa4.com',
    'vhxqa6.com',
    'vimeo-staging.com',
    'vimeo-staging2.com',
    'vimeo.com',
    'vimeo.fr',
    'vimeobusiness.com',
    'vimeocdn.com',
    'vimeogoods.com',
    'vimeoondemand.com',
    'vimeostatus.com'
  ] },
  { name: "Wikipedia", domains: [
    'mediawiki.org',
    'toolforge.org',
    'w.wiki',
    'wikibooks.org',
    'wikidata.org',
    'wikimedia.org',
    'wikimediacloud.org',
    'wikimediafoundation.org',
    'wikinews.org',
    'wikipedia.org',
    'wikiquote.org',
    'wikisource.org',
    'wikiversity.org',
    'wikivoyage.org',
    'wiktionary.org',
    'wmcloud.org',
    'wmflabs.org',
    'wmfusercontent.org'
  ] },
  { name: "Bluesky", domains: [
    'bsky.app',
    'bsky.network',
    'bsky.social'
  ] },
  { name: "Discord", domains: [
    'discord-attachments-uploads-prd.storage.googleapis.com',
    'discord.com',
    'discord.gg',
    'discord.media',
    'discordapp.com',
    'discordapp.net'
  ] },
  { name: "DuckDuckGo", domains: [
    'cispaletter.com',
    'cispaletter.org',
    'cometotheduckside.com',
    'ddg.co',
    'ddg.gg',
    'ddh.gg',
    'dgg.gg',
    'dontbubble.us',
    'donttrack.us',
    'duck.ai',
    'duck.co',
    'duck.com',
    'duckduckco.com',
    'duckduckco.de',
    'duckduckgo.ca',
    'duckduckgo.co',
    'duckduckgo.co.uk',
    'duckduckgo.com',
    'duckduckgo.com.mx',
    'duckduckgo.com.tw',
    'duckduckgo.de',
    'duckduckgo.dk',
    'duckduckgo.in',
    'duckduckgo.jp',
    'duckduckgo.ke',
    'duckduckgo.mx',
    'duckduckgo.nl',
    'duckduckgo.org',
    'duckduckgo.pl',
    'duckduckgo.sg',
    'duckduckgo.uk',
    'duckduckhack.com',
    'duckgo.com',
    'ducksear.ch',
    'duckside.com',
    'dukgo.com',
    'enteentegeh.de',
    'fixtracking.com',
    'goduckgo.com',
    'hacksear.ch',
    'justduckit.com',
    'privacysimplified.com',
    'privatebrowsingmyths.com',
    'spreadprivacy.com'
  ] },
  { name: "Google", domains: [
  ] },
  { name: "Instagram", domains: [
    'cdninstagram.com',
    'fbcdn.net',
    'instagram.com'
  ] },
  { name: "Medium", domains: [
    'medium.com',
    'medium.systems'
  ] },
  { name: "Meta (все сервисы)", domains: [
  ] },
  { name: "Patreon", domains: [
    'live-patreon-marketing.pantheonsite.io',
    'patreon.com',
    'patreoncommunity.com',
    'patreonusercontent.com'
  ] },
  { name: "Pinterest", domains: [
    'pin.it',
    'pinimg.com',
    'pinimg.com.cdn.cloudflare.net',
    'pinterest.at',
    'pinterest.be',
    'pinterest.ca',
    'pinterest.ch',
    'pinterest.cl',
    'pinterest.co',
    'pinterest.co.at',
    'pinterest.co.in',
    'pinterest.co.kr',
    'pinterest.co.nz',
    'pinterest.co.uk',
    'pinterest.com',
    'pinterest.com.au',
    'pinterest.com.bo',
    'pinterest.com.ec',
    'pinterest.com.mx',
    'pinterest.com.pe',
    'pinterest.com.py',
    'pinterest.com.uy',
    'pinterest.com.vn',
    'pinterest.de',
    'pinterest.dk',
    'pinterest.ec',
    'pinterest.engineering',
    'pinterest.es',
    'pinterest.fr',
    'pinterest.hu',
    'pinterest.id',
    'pinterest.ie',
    'pinterest.in',
    'pinterest.info',
    'pinterest.it',
    'pinterest.jp',
    'pinterest.kr',
    'pinterest.map.fastly.net',
    'pinterest.mx',
    'pinterest.net',
    'pinterest.nl',
    'pinterest.nz',
    'pinterest.pe',
    'pinterest.ph',
    'pinterest.pt',
    'pinterest.ru',
    'pinterest.se',
    'pinterest.th',
    'pinterest.tw',
    'pinterest.uk',
    'pinterest.vn',
    'pinterestmail.com'
  ] },
  { name: "Reddit", domains: [
    'redd.it',
    'reddit.app.link',
    'reddit.com',
    'reddit.map.fastly.net',
    'redditblog.com',
    'reddithelp.com',
    'redditinc.com',
    'redditmail.com',
    'redditmedia.com',
    'redditspace.com',
    'redditstatic.com',
    'redditstatus.com'
  ] },
  { name: "Signal", domains: [
    'signal.art',
    'signal.group',
    'signal.link',
    'signal.me',
    'signal.org',
    'signal.tube',
    'signalusers.org',
    'whispersystems.org'
  ] },
  { name: "Telegram", domains: [
    't.me',
    'telegram.org'
  ] },
  { name: "Threads", domains: [
    'threads.com',
    'threads.net'
  ] },
  { name: "TikTok", domains: [
    'akamaized.net',
    'byteoversea.com',
    'ibytedtos.com',
    'ibyteimg.com',
    'muscdn.com',
    'musical.ly',
    'tik-tokapi.com',
    'tiktok.com',
    'tiktokcdn-eu.com',
    'tiktokcdn-us.com',
    'tiktokcdn.com',
    'tiktokv.com',
    'ttwstatic.com'
  ] },
  { name: "WhatsApp", domains: [
    'whatsapp.com',
    'whatsapp.net'
  ] },
  { name: "X (Twitter)", domains: [
    't.co',
    'twimg.com',
    'twitter.com',
    'x.com'
  ] },
  { name: "YouTube", domains: [
    'ggpht.com',
    'googlevideo.com',
    'youtu.be',
    'youtube.com',
    'youtubei.googleapis.com',
    'youtubekids.com',
    'ytimg.com'
  ] },
];

async function loadDnsRoutes() {
  try {
    const res = await xhr('GET', '/dns/routes');
    if (res.ok) {
      const routes = await res.json();
      renderDnsRouteList(routes);
    }
  } catch (e) {
    console.error('loadDnsRoutes error:', e);
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
    const domainCount = domains.length;
    const cidrCount = 0;
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
        <div class="card-route"><span class="backend-badge badge-ndms">${backendLabel}</span></div>
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
    await xhr('POST', '/dns/routes/update', { id, enabled: !route.enabled });
    loadDnsRoutes();
  } catch (e) {
    alert('Ошибка: ' + e.message);
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
  if (!route) route = { id: '', name: '', domains: [], enabled: true };

  const nameInput = document.getElementById('dnsRouteName');
  const domainsInput = document.getElementById('dnsRouteDomains');
  if (nameInput) nameInput.value = route.name || '';
  if (domainsInput) domainsInput.value = (route.domains || []).join('\n');

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
  if (!nameInput || !domainsInput) return;

  const name = nameInput.value.trim();
  if (!name) return alert('Введите название');

  const domains = domainsInput.value.split('\n').map(s => s.trim()).filter(s => s !== '');
  if (!domains.length) return alert('Добавьте хотя бы один домен');

  const payload = { name, domains, enabled: true };
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
  if (!domainsInput) return;
  const existing = domainsInput.value.split('\n').map(s => s.trim()).filter(s => s !== '');
  const merged = [...new Set([...existing, ...preset.domains])];
  domainsInput.value = merged.join('\n');
}

async function refresh() {
	try {
		const peers = await loadPeers();
		const status = await loadStatus();
		saveExpandedInputs();
		renderPeers(peers);
		restoreExpandedInputs();
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
}

function saveExpandedInputs() {
	const ae = document.activeElement;
	if (ae && ae.tagName === 'INPUT') {
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
		};
		const res = await xhr('POST', '/config/save', cfg);
		if (res.ok) alert('Настройки сохранены. Сервер перезапущен.');
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
	document.getElementById('serverForm').addEventListener('submit', saveConfig);
	switchTab('peers', document.querySelector('.tab'));
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

async function loadLogs() {
	try {
		const res = await xhr('GET', '/logs');
		if (res.ok) {
			document.getElementById('logOutput').textContent = res.text();
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
});
