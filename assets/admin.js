const fmt = (t) => t ? new Date(t * 1000).toISOString().slice(0, 16).replace('T', ' ') : '—';

// Each admin page shows one list; the template names it.
const section = document.getElementById('admin').dataset.section;
const rows = document.getElementById('rows');

function cell(text) {
  const td = document.createElement('td');
  td.textContent = text;
  return td;
}

function fail(result, fallback) {
  xfail(document.getElementById('m'), result, fallback);
}

function requestedPage() {
  // Past-the-end is the server's to clamp, but only within i64: a huge number
  // would be a 400, not the last page.
  const n = parseInt(new URLSearchParams(location.search).get('page'), 10);
  return Number.isSafeInteger(n) && n > 0 ? n : 1;
}

function pageLink(label, page, enabled) {
  if (!enabled) {
    const span = document.createElement('span');
    span.className = 'pager__off';
    span.textContent = label;
    return span;
  }
  const a = document.createElement('a');
  a.href = '?page=' + page;
  a.textContent = label;
  return a;
}

// Prev/next under the table. Plain links, so back/forward and a bookmark keep
// the page; the server clamps a page past the end and the URL follows it.
function renderPager(data) {
  const nav = document.getElementById('pager');
  nav.textContent = '';
  const last = Math.max(1, Math.ceil(data.total / data.per_page));
  if (data.page !== requestedPage()) {
    history.replaceState(null, '', data.page === 1 ? location.pathname : '?page=' + data.page);
  }
  nav.hidden = last <= 1;
  if (nav.hidden) return;
  const info = document.createElement('span');
  info.textContent = 'page ' + data.page + ' of ' + last + ' · ' + data.total + ' total';
  nav.append(
    pageLink('← prev', data.page - 1, data.page > 1),
    info,
    pageLink('next →', data.page + 1, data.page < last),
  );
}

let meId = null;

const renderers = {
  users(u) {
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
        if (next && !await xask(
          'disable ' + u.email + '? they cannot sign in or use their tokens until enabled again.',
          'disable',
        )) return;
        const res = await xreq('PATCH', '/v1/admin/users/' + encodeURIComponent(u.id), { disabled: next });
        if (!res.ok) { fail(res, 'could not update the account'); return; }
        loadPage();
      });
      td.append(button);
    }
    tr.append(td);
    return tr;
  },

  projects(p) {
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
      loadPage();
    });
    td.append(button);
    tr.append(td);
    return tr;
  },

  resources(res) {
    const tr = document.createElement('tr');
    const project = document.createElement('td');
    const projectLink = document.createElement('a');
    projectLink.href = '/p/' + encodeURIComponent(res.project.slug);
    projectLink.textContent = res.project.slug;
    project.append(projectLink);
    const title = document.createElement('td');
    const titleLink = document.createElement('a');
    titleLink.href = '/r/' + encodeURIComponent(res.project.slug) + '/' + res.kind + '/' + res.slug;
    titleLink.textContent = res.title;
    title.append(titleLink);
    tr.append(
      project,
      cell(res.kind),
      title,
      cell(fmt(res.updated_at)),
    );
    const td = document.createElement('td');
    const button = document.createElement('button');
    button.className = 'ghost';
    button.textContent = 'remove';
    button.addEventListener('click', async () => {
      if (!await xask(
        'remove ' + res.title + '? it disappears from the project. this cannot be undone.',
        'remove',
      )) return;
      const out = await xreq('DELETE', '/v1/admin/resources/' + encodeURIComponent(res.id));
      if (!out.ok) { fail(out, 'could not remove the resource'); return; }
      loadPage();
    });
    td.append(button);
    tr.append(td);
    return tr;
  },

  invites(inv) {
    const tr = document.createElement('tr');
    const status = inviteStatus(inv, Date.now() / 1000);
    if (status !== 'unused') tr.className = 'is-disabled';
    tr.append(
      cell(status),
      cell(fmt(inv.created_at)),
      cell(fmt(inv.expires_at)),
      cell(inv.created_by.display_name || inv.created_by.email),
      cell(inv.used_by ? (inv.used_by.display_name || inv.used_by.email) : '—'),
    );
    return tr;
  },
};

function inviteStatus(inv, now) {
  if (inv.used_at) return 'used';
  if (inv.expires_at <= now) return 'expired';
  return 'unused';
}

async function loadPage(page = requestedPage()) {
  const r = await xreq('GET', '/v1/admin/' + section + '?page=' + page);
  if (r.status === 401) { location.href = '/login'; return; }
  if (r.status === 403) { location.href = '/'; return; }
  if (!r.ok) { fail(r, 'could not load ' + section); return; }
  const items = Array.isArray(r.data.items) ? r.data.items : [];
  rows.textContent = '';
  document.getElementById('none').hidden = items.length > 0;
  for (const item of items) rows.append(renderers[section](item));
  renderPager(r.data);
}

const mint = document.getElementById('mint');
if (mint) {
  mint.addEventListener('click', async () => {
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
    // Newest first: the code just minted is at the top of page one.
    loadPage(1);
  });
}

async function load() {
  if (section === 'users') {
    const me = await xreq('GET', '/v1/me');
    if (me.status === 401) { location.href = '/login'; return; }
    if (!me.ok) { fail(me, 'could not load the current account'); return; }
    meId = me.data.user && me.data.user.id;
  }
  await loadPage();
}

load();
