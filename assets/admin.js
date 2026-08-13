const fmt = (t) => t ? new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';

function cell(text) {
  const td = document.createElement('td');
  td.textContent = text;
  return td;
}

function fail(result, fallback) {
  xfail(document.getElementById('m'), result, fallback);
}

async function loadUsers() {
  const r = await xreq('GET', '/v1/admin/users');
  if (r.status === 401) { location.href = '/login'; return; }
  if (r.status === 403) { location.href = '/'; return; }
  if (!r.ok) { fail(r, 'could not load users'); return; }
  const users = Array.isArray(r.data) ? r.data : [];
  const rows = document.getElementById('users');
  rows.textContent = '';
  document.getElementById('users-none').hidden = users.length > 0;
  for (const u of users) {
    const tr = document.createElement('tr');
    if (u.disabled_at) tr.className = 'is-disabled';
    tr.append(
      cell(u.display_name),
      cell(u.email),
      cell(u.is_admin ? 'admin' : 'member'),
      cell(String(u.project_count)),
      cell(fmt(u.created_at)),
    );
    const td = document.createElement('td');
    const self = meId && u.id === meId;
    if (!self) {
      const button = document.createElement('button');
      button.className = 'ghost';
      button.textContent = u.disabled_at ? 'enable' : 'disable';
      button.addEventListener('click', async () => {
        const next = !u.disabled_at;
        if (next && !confirm('disable ' + u.email + '? they cannot sign in or use their tokens until enabled again.')) return;
        const res = await xreq('PATCH', '/v1/admin/users/' + encodeURIComponent(u.id), { disabled: next });
        if (!res.ok) { fail(res, 'could not update the account'); return; }
        loadUsers();
      });
      td.append(button);
    }
    tr.append(td);
    rows.append(tr);
  }
}

async function loadProjects() {
  const r = await xreq('GET', '/v1/admin/projects');
  if (!r.ok) { fail(r, 'could not load projects'); return; }
  const projects = Array.isArray(r.data) ? r.data : [];
  const rows = document.getElementById('projects');
  rows.textContent = '';
  document.getElementById('projects-none').hidden = projects.length > 0;
  for (const p of projects) {
    const tr = document.createElement('tr');
    const name = document.createElement('td');
    const a = document.createElement('a');
    a.href = '/p/' + encodeURIComponent(p.slug);
    a.textContent = p.slug;
    name.append(a);
    const vis = document.createElement('td');
    vis.className = p.is_public ? 'state state--public' : 'state state--private';
    vis.textContent = p.is_public ? 'public' : 'private';
    tr.append(
      name,
      cell(p.owner.display_name || p.owner.email),
      vis,
      cell(String(p.resource_count)),
    );
    const td = document.createElement('td');
    const button = document.createElement('button');
    button.className = 'ghost';
    button.textContent = p.is_public ? 'make private' : 'make public';
    button.addEventListener('click', async () => {
      const next = !p.is_public;
      const res = await xreq('PATCH', '/v1/admin/projects/' + encodeURIComponent(p.slug), { is_public: next });
      if (!res.ok) { fail(res, 'could not update the project'); return; }
      loadProjects();
    });
    td.append(button);
    tr.append(td);
    rows.append(tr);
  }
}

function inviteStatus(inv, now) {
  if (inv.used_at) return 'used';
  if (inv.expires_at <= now) return 'expired';
  return 'unused';
}

async function loadInvites() {
  const r = await xreq('GET', '/v1/admin/invites');
  if (!r.ok) { fail(r, 'could not load invites'); return; }
  const invites = Array.isArray(r.data) ? r.data : [];
  const rows = document.getElementById('invites');
  rows.textContent = '';
  document.getElementById('invites-none').hidden = invites.length > 0;
  const now = Date.now() / 1000;
  for (const inv of invites) {
    const tr = document.createElement('tr');
    const status = inviteStatus(inv, now);
    if (status !== 'unused') tr.className = 'is-disabled';
    tr.append(
      cell(status),
      cell(fmt(inv.created_at)),
      cell(fmt(inv.expires_at)),
      cell(inv.created_by.display_name || inv.created_by.email),
      cell(inv.used_by ? (inv.used_by.display_name || inv.used_by.email) : '—'),
    );
    rows.append(tr);
  }
}

document.getElementById('mint').addEventListener('click', async () => {
  const m = document.getElementById('m');
  m.className = 'msg';
  m.textContent = 'creating…';
  const r = await xreq('POST', '/v1/invites', {});
  if (r.status === 401) { location.href = '/login'; return; }
  if (!r.ok) { fail(r, 'could not create the invite'); return; }
  m.className = 'msg ok';
  m.textContent = 'created — copy the code below now, it is not shown again';
  const box = document.getElementById('secret');
  box.textContent = '';
  const pre = document.createElement('div');
  pre.className = 'secret';
  pre.textContent = r.data.code;
  box.append(pre);
  loadInvites();
});

let meId = null;

async function load() {
  const me = await xreq('GET', '/v1/me');
  if (me.status === 401) { location.href = '/login'; return; }
  if (!me.ok) { fail(me, 'could not load the current account'); return; }
  meId = me.data.user && me.data.user.id;
  await loadUsers();
  await loadProjects();
  await loadInvites();
}

load();
