package main

// loginPageHTML — минимальная страница входа, отдаваемая без авторизации.
// Встроена в бинарник и не содержит ни структуры приложения, ни статики:
// после входа браузер получает полный интерфейс (templates/index.html).
const loginPageHTML = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Вход</title>
<style>
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  background: #0f172a; color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; }
form { display: flex; flex-direction: column; gap: 12px; width: 260px; }
input { padding: 10px; border: 1px solid #334155; border-radius: 6px; background: #1e293b;
  color: #e2e8f0; font-size: 1rem; }
input:focus { outline: none; border-color: #38bdf8; }
button { padding: 10px; border: none; border-radius: 6px; background: #38bdf8; color: #0f172a;
  font-size: 1rem; font-weight: 600; cursor: pointer; }
button:hover { background: #7dd3fc; }
.err { color: #f87171; font-size: 0.85rem; min-height: 1.2em; text-align: center; }
</style>
</head>
<body>
<form id="f">
  <input type="password" id="p" placeholder="Пароль" autofocus autocomplete="current-password">
  <button type="submit">Войти</button>
  <div class="err" id="e"></div>
</form>
<form id="c" style="display:none">
  <input type="password" id="np" placeholder="Новый пароль" autocomplete="new-password">
  <button type="submit">Сохранить</button>
  <div class="err"></div>
</form>
<script>
(function () {
  var KEY = 'ncmanager_token';
  function err(m) { document.getElementById('e').textContent = m || ''; }
  function post(path, body, token) {
    var h = { 'Content-Type': 'application/json' };
    if (token) h['Authorization'] = 'Bearer ' + token;
    return fetch(path, { method: 'POST', headers: h, body: JSON.stringify(body || {}) });
  }
  // Миграция старых сессий: токен из localStorage проверяется и
  // переносится в HttpOnly-куку через служебный редирект.
  var old = null;
  try { old = localStorage.getItem(KEY); } catch (e) {}
  if (old) {
    fetch('/api/version', { headers: { 'Authorization': 'Bearer ' + old } })
      .then(function (r) {
        if (r.ok) { location.replace('/?token=' + encodeURIComponent(old)); }
        else { try { localStorage.removeItem(KEY); } catch (e) {} }
      })
      .catch(function () {});
  }
  document.getElementById('f').onsubmit = function (ev) {
    ev.preventDefault();
    err('');
    post('/api/login', { password: document.getElementById('p').value })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (x) {
        if (!x.ok) { err('Неверный пароль'); return; }
        try { localStorage.setItem(KEY, x.d.token); } catch (e) {}
        if (x.d.requirePasswordChange === 'true') {
          window._t = x.d.token;
          document.getElementById('f').style.display = 'none';
          document.getElementById('c').style.display = '';
          document.getElementById('np').focus();
        } else {
          location.replace('/');
        }
      })
      .catch(function () { err('Сервер недоступен'); });
  };
  document.getElementById('c').onsubmit = function (ev) {
    ev.preventDefault();
    post('/api/auth/change-password', { newPassword: document.getElementById('np').value }, window._t)
      .then(function (r) {
        if (r.ok) { location.replace('/'); }
        else { document.querySelector('#c .err').textContent = 'Не удалось сменить пароль'; }
      });
  };
})();
</script>
</body>
</html>
`
