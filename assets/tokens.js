const fmt = (t) => t ? new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') : 'never';

async function load() {
  const r = await xreq('GET', '/v1/tokens');
  if (r.status === 401) { location.href = '/login'; return; }
  if (!r.ok) { xfail(document.getElementById('m'), r, 'could not load tokens'); return; }
  const tokens = Array.isArray(r.data) ? r.data : [];
  const rows = document.getElementById('rows');
  rows.textContent = '';
  document.getElementById('none').hidden = tokens.length > 0;
  for (const t of tokens) {
    const tr = document.createElement('tr');
    for (const value of [t.id, t.label, t.scopes.join(' '), t.project || '—', fmt(t.last_used_at)]) {
      const td = document.createElement('td');
      td.textContent = value;
      tr.append(td);
    }
    const td = document.createElement('td');
    const button = document.createElement('button');
    button.className = 'ghost';
    button.textContent = 'revoke';
    button.addEventListener('click', async () => {
      if (!await xask(
        'revoke ' + t.label + '? clients using it stop working immediately.',
        'revoke',
      )) return;
      const r = await xreq('DELETE', '/v1/tokens/' + encodeURIComponent(t.id));
      if (!r.ok) { xfail(document.getElementById('m'), r, 'revoke failed'); return; }
      load();
    });
    td.append(button);
    tr.append(td);
    rows.append(tr);
  }
}

document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const m = document.getElementById('m');
  m.className = 'msg'; m.textContent = 'creating…';
  const scopes = [...document.querySelectorAll('.scopes input:checked')].map((i) => i.value);
  const days = parseInt(document.getElementById('days').value, 10);
  const r = await xreq('POST', '/v1/tokens', {
    label: document.getElementById('label').value,
    scopes,
    project: document.getElementById('project').value || null,
    expires_in_days: Number.isFinite(days) ? days : null,
  });
  if (r.status === 401) { location.href = '/login'; return; }
  if (!r.ok) { xfail(m, r, 'could not create the token'); return; }
  const data = r.data;
  m.className = 'msg ok';
  m.textContent = 'created — copy the secret below now, it is not shown again';
  const box = document.getElementById('secret');
  box.textContent = '';
  const pre = document.createElement('div');
  pre.className = 'secret';
  pre.textContent = data.token;
  box.append(pre);
  load();
});

load();
