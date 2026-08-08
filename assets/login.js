document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const m = document.getElementById('m');
  m.className = 'msg'; m.textContent = 'signing in…';
  const r = await xreq('POST', '/v1/auth/login', {
    email: document.getElementById('email').value,
    password: document.getElementById('password').value,
  });
  if (r.ok) { location.href = '/'; return; }
  xfail(m, r, 'sign in failed');
});
