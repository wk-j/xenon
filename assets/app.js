// Shared fetch helpers. Every form goes through these so a dead server or a
// dropped connection reports "cannot reach the server" instead of leaving the
// page stuck on its in-progress message forever.
//
// Destructive actions use `xask`, not `window.confirm`: the OS dialog is a
// different surface, cannot be styled, and is easy to miss or to dismiss by
// habit. The in-page prompt is cancel-first (Escape and the focused button
// both bail) so a stray Enter does not commit.
async function xreq(method, url, body) {
  try {
    const init = { method };
    if (body !== undefined) {
      init.headers = { 'content-type': 'application/json' };
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    let data = {};
    try { data = await res.json(); } catch (_) { /* empty or non-JSON body */ }
    return { ok: res.ok, status: res.status, data };
  } catch (_) {
    return { ok: false, status: 0, data: {}, offline: true };
  }
}
function xfail(el, result, fallback) {
  el.className = 'msg err';
  el.textContent = result.offline
    ? 'cannot reach the server — is it still running?'
    : (result.data.message || fallback);
}

function xask(message, action) {
  return new Promise((resolve) => {
    const prev = document.getElementById('xask');
    if (prev) prev.dispatchEvent(new Event('xask-cancel'));

    const box = document.createElement('div');
    box.id = 'xask';
    box.className = 'ask';
    box.setAttribute('role', 'alertdialog');
    box.setAttribute('aria-modal', 'true');
    box.setAttribute('aria-describedby', 'xask-msg');

    const p = document.createElement('p');
    p.id = 'xask-msg';
    p.className = 'ask__msg';
    p.textContent = message;

    const actions = document.createElement('div');
    actions.className = 'ask__actions';
    const no = document.createElement('button');
    no.type = 'button';
    no.className = 'ghost';
    no.textContent = 'cancel';
    const yes = document.createElement('button');
    yes.type = 'button';
    yes.textContent = action || 'confirm';
    actions.append(no, yes);
    box.append(p, actions);

    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      document.removeEventListener('keydown', onKey);
      box.remove();
      resolve(ok);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        finish(false);
      }
    };
    no.addEventListener('click', () => finish(false));
    yes.addEventListener('click', () => finish(true));
    box.addEventListener('xask-cancel', () => finish(false));
    document.addEventListener('keydown', onKey);

    document.body.append(box);
    no.focus();
  });
}
