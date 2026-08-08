// Shared fetch helpers. Every form goes through these so a dead server or a
// dropped connection reports "cannot reach the server" instead of leaving the
// page stuck on its in-progress message forever.
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
