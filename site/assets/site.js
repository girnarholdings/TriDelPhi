(() => {
  const root = document.documentElement;
  const button = document.getElementById('theme');
  if (!button) return;
  let preference;
  try { preference = localStorage.getItem('tridelphi-theme'); } catch (_) { /* Storage can be blocked. */ }
  if (preference === 'light' || preference === 'dark') root.dataset.theme = preference;
  const system = window.matchMedia('(prefers-color-scheme: light)');
  const current = () => root.dataset.theme || (system.matches ? 'light' : 'dark');
  const sync = () => {
    const label = current() === 'dark' ? 'Light theme' : 'Dark theme';
    button.textContent = label;
    button.setAttribute('aria-label', `Use ${label.toLowerCase()}`);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = current() === 'dark' ? '#0b1730' : '#f6f8fc';
  };
  button.hidden = false;
  button.addEventListener('click', () => {
    root.dataset.theme = current() === 'dark' ? 'light' : 'dark';
    try { localStorage.setItem('tridelphi-theme', root.dataset.theme); } catch (_) { /* Theme still works for this page. */ }
    sync();
  });
  system.addEventListener('change', sync);
  sync();
})();
