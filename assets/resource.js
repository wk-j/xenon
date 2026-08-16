const btn = document.getElementById('remove');
if (btn) {
  btn.addEventListener('click', async () => {
    const title = btn.dataset.title || 'this resource';
    const ok = await xask(
      'remove ' + title + '? it disappears from the project. this cannot be undone.',
      'remove',
    );
    if (!ok) return;
    const r = await xreq('DELETE', '/v1/admin/resources/' + encodeURIComponent(btn.dataset.id));
    if (!r.ok) {
      xfail(document.getElementById('m'), r, 'could not remove the resource');
      return;
    }
    location.href = '/p/' + encodeURIComponent(btn.dataset.project) + '/resources';
  });
}
