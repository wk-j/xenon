document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const m = document.getElementById('m');
  m.className = 'msg'; m.textContent = 'creating…';
  const r = await xreq('POST', '/v1/auth/register', {
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
    display_name: document.getElementById('display_name').value || null,
    invite: document.getElementById('invite').value || null,
  });
  if (r.ok) { location.href = '/settings/tokens'; return; }
  xfail(m, r, 'registration failed');
});
