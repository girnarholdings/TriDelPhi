import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';

const source = readFileSync(new URL('../site/assets/site.js', import.meta.url), 'utf8');
function page({ stored = null, light = false, blocked = false } = {}) {
  const root = { dataset: {} };
  const meta = {};
  const callbacks = {};
  const button = { hidden: true, setAttribute(k, v) { this[k] = v; },
    addEventListener(k, v) { callbacks[k] = v; } };
  const system = { matches: light, addEventListener(k, v) { callbacks[k] = v; } };
  const writes = [];
  runInNewContext(source, {
    document: { documentElement: root, getElementById: () => button, querySelector: () => meta },
    window: { matchMedia: () => system },
    localStorage: {
      getItem() { if (blocked) throw Error('Storage denied'); return stored; },
      setItem(k, v) { if (blocked) throw Error('Storage denied'); writes.push([k, v]); },
    },
  });
  return { root, button, meta, callbacks, system, writes };
}

test('system preference works without a saved setting', () => {
  const p = page({ light: true });
  assert.equal(p.button.hidden, false);
  assert.equal(p.button['aria-label'], 'Use dark theme');
  assert.equal(p.meta.content, '#f6f8fc');
  p.system.matches = false;
  p.callbacks.change();
  assert.equal(p.meta.content, '#0b1730');
});

test('explicit preference survives system changes and toggles accessibly', () => {
  const p = page({ stored: 'dark', light: true });
  p.callbacks.change();
  assert.equal(p.root.dataset.theme, 'dark');
  p.callbacks.click();
  assert.equal(p.root.dataset.theme, 'light');
  assert.equal(p.button.textContent, 'Dark theme');
  assert.deepEqual(p.writes, [['tridelphi-theme', 'light']]);
});

test('blocked storage does not disable the theme control', () => {
  const p = page({ blocked: true });
  p.callbacks.click();
  assert.equal(p.root.dataset.theme, 'light');
  assert.equal(p.meta.content, '#f6f8fc');
});

test('invalid stored values cannot become theme names', () => {
  const p = page({ stored: 'broken' });
  assert.equal(p.root.dataset.theme, undefined);
  assert.equal(p.button.textContent, 'Light theme');
});
