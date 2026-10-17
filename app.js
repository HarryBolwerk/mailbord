// Mailbord offline — read-only, works without internet.
// Data is encrypted (AES-256-GCM). The data key is wrapped per device with that device's RSA-OAEP public key;
// the private key is generated here, is non-extractable and never leaves this device.
'use strict';

const $ = id => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const norm = s => (s || '').toLowerCase();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');

/* ---------- tiny IndexedDB key-value store ---------- */
const idb = (() => {
  let p;
  const open = () => p || (p = new Promise((ok, bad) => {
    const r = indexedDB.open('mailbord', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => ok(r.result); r.onerror = () => bad(r.error);
  }));
  const tx = async (mode, fn) => { const db = await open(); return new Promise((ok, bad) => { const t = db.transaction('kv', mode); const s = t.objectStore('kv'); const r = fn(s); t.oncomplete = () => ok(r && r.result); t.onerror = () => bad(t.error); }); };
  return { get: k => tx('readonly', s => s.get(k)), set: (k, v) => tx('readwrite', s => s.put(v, k)), del: k => tx('readwrite', s => s.delete(k)) };
})();

/* ---------- keys ---------- */
async function deviceKey() {
  let dk = await idb.get('device');
  if (dk) return dk;
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['decrypt', 'unwrapKey']);
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  const id = hex(await crypto.subtle.digest('SHA-256', spki)).slice(0, 16);
  dk = { id, publicKey: b64(spki), privateKey: pair.privateKey, created: new Date().toISOString() };
  await idb.set('device', dk);
  return dk;
}
function pairingCode(dk) {
  const ua = navigator.userAgent;
  const name = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iPhone' : /Mac/.test(ua) ? 'Mac' : /Windows/.test(ua) ? 'Windows' : 'Toestel';
  return 'MB1:' + dk.id + ':' + name + ':' + dk.publicKey;
}
async function dataKey(dk, force) {
  if (!force) { const k = await idb.get('datakey'); if (k) return k; }
  const r = await fetch('data/keys.json?t=' + Date.now());
  if (!r.ok) throw Object.assign(new Error('keys'), { code: 'nokeys' });
  const keys = await r.json();
  const mine = (keys.devices || []).find(d => d.id === dk.id);
  if (!mine) throw Object.assign(new Error('not paired'), { code: 'unpaired' });
  const k = await crypto.subtle.unwrapKey('raw', unb64(mine.wrapped), dk.privateKey, { name: 'RSA-OAEP' }, { name: 'AES-GCM' }, false, ['decrypt']);
  await idb.set('datakey', k);
  return k;
}
async function decrypt(key, buf) {
  const u = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
}

/* ---------- state ---------- */
const state = { cards: [], generated: null, fromCache: false, q: '', tag: null, bodies: new Map() };
const open = new Set();
let KEY = null;

function setStatus(text, online) { $('status').textContent = text; $('dot').classList.toggle('off', !online); }
function fmtShort(iso) {
  if (!iso) return '';
  const d = new Date(iso), now = new Date();
  const day = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(d)) / 864e5);
  if (diff === 0) return d.toLocaleTimeString('nl-NL', { hour: '2-digit', minute: '2-digit' });
  if (diff === 1) return 'gisteren';
  if (diff < 7) return d.toLocaleDateString('nl-NL', { weekday: 'short' });
  return d.toLocaleDateString('nl-NL', { day: 'numeric', month: 'short' });
}
const fmtFull = iso => { try { return new Date(iso).toLocaleString('nl-NL', { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }); } catch { return ''; } };
const tagsOf = c => Array.isArray(c.tags) ? c.tags : [];
const mailsOf = c => Array.isArray(c.mails) ? c.mails : [];
const lastDate = c => mailsOf(c).reduce((m, x) => (x.date || '') > m ? x.date : m, c.updated || '');
const byNewest = (a, b) => (!!a.quiet - !!b.quiet) || lastDate(b).localeCompare(lastDate(a));

/* ---------- load ---------- */
async function loadIndex() {
  const r = await fetch('data/index.bin?t=' + Date.now());
  if (!r.ok) throw new Error('index ' + r.status);
  state.fromCache = r.headers.get('x-from-cache') === '1';
  const plain = await decrypt(KEY, await r.arrayBuffer());
  const idx = JSON.parse(new TextDecoder().decode(plain));
  state.cards = idx.cards || []; state.generated = idx.generated;
}
function statusLine(extra) {
  const online = navigator.onLine && !state.fromCache;
  const base = state.generated ? (online ? 'bijgewerkt ' : 'offline · versie van ') + fmtShort(state.generated) : '';
  setStatus(base + (extra ? ' · ' + extra : ''), online);
}
async function prefetchAll() {
  const files = [];
  state.cards.forEach(c => mailsOf(c).forEach(m => { if (m.body) files.push('data/m/' + m.body + '.bin'); (m.attachments || []).forEach(a => files.push('data/a/' + a.file + '.bin')); }));
  let done = 0, failed = 0;
  const queue = [...new Set(files)];
  const total = queue.length;
  const worker = async () => { while (queue.length) { const f = queue.shift(); try { const r = await fetch(f); if (!r.ok) failed++; else await r.arrayBuffer(); } catch { failed++; } done++; if (done % 5 === 0 || done === total) statusLine(failed ? `${done - failed}/${total} offline` : (done < total ? `offline opslaan ${done}/${total}` : 'alles offline')); } };
  await Promise.all([worker(), worker(), worker()]);
  statusLine(failed ? `${total - failed}/${total} offline beschikbaar` : 'alles offline beschikbaar');
}
async function body(m) {
  if (!m.body) return '';
  if (state.bodies.has(m.body)) return state.bodies.get(m.body);
  const r = await fetch('data/m/' + m.body + '.bin');
  if (!r.ok) throw new Error('body');
  const t = new TextDecoder().decode(await decrypt(KEY, await r.arrayBuffer()));
  state.bodies.set(m.body, t); return t;
}

/* ---------- search ---------- */
function highlight(text, q) {
  const frag = document.createDocumentFragment();
  if (!q) { frag.append(text); return frag; }
  const t = norm(text); let i = 0, j;
  while ((j = t.indexOf(q, i)) !== -1) { frag.append(text.slice(i, j)); frag.append(el('mark', null, text.slice(j, j + q.length))); i = j + q.length; }
  frag.append(text.slice(i)); return frag;
}
const mailHits = (m, q) => !q || [m.subject, m.from, m.gist].some(s => norm(s).includes(q)) || norm(state.bodies.get(m.body)).includes(q);
function cardHits(c, q) {
  if (state.tag && !tagsOf(c).includes(state.tag)) return false;
  if (!q) return true;
  if ([c.title, c.ref, c.summary, c.status, ...tagsOf(c)].some(s => norm(s).includes(q))) return true;
  return mailsOf(c).some(m => mailHits(m, q));
}
let bodiesLoaded = false;
async function loadAllBodies() {
  if (bodiesLoaded) return; bodiesLoaded = true;
  for (const c of state.cards) for (const m of mailsOf(c)) { try { await body(m); } catch {} }
  render();
}

/* ---------- render ---------- */
function render() {
  const q = state.q, feed = $('feed');
  feed.textContent = '';
  const cards = state.cards.filter(c => cardHits(c, q)).sort(byNewest);
  const f = $('filters'); f.textContent = '';
  if (state.tag) { const t = el('button', 'tag on'); t.type = 'button'; t.append(state.tag, el('span', 'x', '×')); t.onclick = () => applyTag(null); f.append(t); }
  if (q || state.tag) f.append(el('span', 'info', cards.length + (cards.length === 1 ? ' kaart' : ' kaarten')));
  if (!cards.length) { feed.append(el('div', 'empty', state.cards.length ? 'Geen kaarten gevonden.' : 'Nog geen mail.')); return; }
  cards.forEach(c => {
    const card = el('article', 'card' + (c.quiet ? ' quiet' : '')); card.dataset.id = c.id;
    const main = el('button', 'main'); main.type = 'button'; main.setAttribute('aria-expanded', open.has(c.id));
    const l1 = el('div', 'line1'); const t = el('span', 'title'); t.append(highlight(c.title || 'Zonder titel', q));
    l1.append(t, el('span', 'when', fmtShort(lastDate(c)))); main.append(l1);
    if (c.summary) { const d = el('div', 'desc'); d.append(highlight(c.summary, q)); main.append(d); }
    const tags = tagsOf(c);
    if (tags.length) {
      const tg = el('div', 'tags');
      tags.forEach(name => { const b = el('span', 'tag' + (state.tag === name ? ' on' : ''), name); b.setAttribute('role', 'button'); b.tabIndex = 0;
        const pick = e => { e.stopPropagation(); applyTag(state.tag === name ? null : name); };
        b.onclick = pick; b.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(e); } }; tg.append(b); });
      main.append(tg);
    }
    main.onclick = () => { open.has(c.id) ? open.delete(c.id) : open.add(c.id); render(); };
    card.append(main);
    if (open.has(c.id) || (q && mailsOf(c).some(m => mailHits(m, q)) && !norm(c.title).includes(q))) {
      const det = el('div', 'detail');
      const facts = el('div', 'facts');
      if (c.status) { const s = el('span'); s.append(el('b', null, c.status)); facts.append(s); }
      if (c.ref) facts.append(el('span', 'mono', c.ref));
      if (facts.childNodes.length) det.append(facts);
      [...mailsOf(c)].sort((a, b) => (b.date || '').localeCompare(a.date || '')).forEach(m => {
        const b = el('button', 'mail'); b.type = 'button';
        const g = el('span', 'gist'); g.append(highlight(m.gist || m.subject || '(geen onderwerp)', q)); b.append(g);
        const meta = el('span', 'mailmeta'); meta.append(el('span', null, m.from || ''), el('span', null, fmtShort(m.date)));
        if (m.attachments && m.attachments.length) meta.append(el('span', null, '📎 ' + m.attachments.length));
        if (m.gist && m.subject) { const s = el('span', 'subj'); s.append(highlight(m.subject, q)); meta.append(s); }
        b.append(meta); b.onclick = () => openMail(m); det.append(b);
      });
      card.append(det);
    }
    feed.append(card);
  });
}

/* ---------- filter animation (same as the board) ---------- */
const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)');
let animating = false;
const cardEls = () => new Map([...document.querySelectorAll('#feed .card')].map(n => [n.dataset.id, n]));
async function applyTag(tag) {
  if (animating) return;
  if (reduceMotion.matches || !Element.prototype.animate) { state.tag = tag; render(); scrollTo({ top: 0 }); return; }
  animating = true;
  const before = cardEls(), firstPos = new Map([...before].map(([id, n]) => [id, n.getBoundingClientRect().top]));
  const keep = new Set(state.cards.filter(c => !tag || tagsOf(c).includes(tag)).map(c => c.id));
  const leaving = [...before].filter(([id]) => !keep.has(id)).map(([, n]) => n);
  [...before].filter(([id]) => keep.has(id)).forEach(([, n]) => n.animate([{ transform: 'scale(1)' }, { transform: 'scale(1.015)' }, { transform: 'scale(1)' }], { duration: 260, easing: 'ease-out' }));
  await Promise.all(leaving.map((n, i) => n.animate([{ opacity: 1, transform: 'none', filter: 'blur(0)' }, { opacity: 0, transform: 'translateY(10px) scale(.96)', filter: 'blur(3px)' }],
    { duration: 130, delay: Math.min(i, 6) * 12, easing: 'cubic-bezier(.4,0,1,1)', fill: 'forwards' }).finished.catch(() => {})));
  state.tag = tag; render(); if (scrollY > 0) scrollTo({ top: 0 });
  let k = 0;
  cardEls().forEach((n, id) => {
    if (firstPos.has(id)) { const dy = firstPos.get(id) - n.getBoundingClientRect().top; if (Math.abs(dy) > 1) n.animate([{ transform: `translateY(${dy}px)` }, { transform: 'none' }], { duration: 420, easing: 'cubic-bezier(.2,.8,.2,1)' }); }
    else n.animate([{ opacity: 0, transform: 'translateY(14px)' }, { opacity: 1, transform: 'none' }], { duration: 320, delay: 80 + Math.min(k++, 8) * 40, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'backwards' });
  });
  setTimeout(() => { animating = false; }, 440);
}

/* ---------- reader ---------- */
function linkify(text) {
  const frag = document.createDocumentFragment(); const re = /https?:\/\/[^\s)\]|>]+/g; let i = 0, m;
  while ((m = re.exec(text))) { frag.append(text.slice(i, m.index)); const a = el('a', null, m[0].length > 60 ? m[0].slice(0, 57) + '…' : m[0]); a.href = m[0]; a.target = '_blank'; a.rel = 'noopener'; frag.append(a); i = m.index + m[0].length; }
  frag.append(text.slice(i)); return frag;
}
let current = null, lastFocus = null, objectUrls = [];
async function openMail(m) {
  lastFocus = document.activeElement; current = m;
  $('rsubj').textContent = m.subject || '(geen onderwerp)';
  $('rgist').textContent = m.gist || ''; $('rgist').hidden = !m.gist;
  $('rmeta').textContent = (m.fromFull || m.from || '') + (m.to ? ' → ' + m.to : '') + ' · ' + fmtFull(m.date);
  const rb = $('rbody'); rb.textContent = 'Mail laden…';
  $('scrim').hidden = false; $('reader').hidden = false; $('rclose').focus();
  let text = '';
  try { text = await body(m); } catch { text = null; }
  if (current !== m) return;
  rb.textContent = '';
  const atts = m.attachments || [];
  if (atts.length) {
    const wrap = el('div', 'atts'), view = el('div', 'attview'); view.hidden = true;
    atts.forEach(a => { const l = el('button', 'att'); l.type = 'button'; l.append(a.name || 'bijlage'); if (a.type) l.append(el('span', null, a.type.split('/').pop().toUpperCase()));
      l.onclick = () => { wrap.querySelectorAll('.att').forEach(x => x.classList.toggle('on', x === l)); showAttachment(a, view); }; wrap.append(l); });
    rb.append(wrap, view);
  }
  if (text === null) rb.append(el('p', 'rmeta', 'Deze mail is nog niet op dit toestel opgeslagen. Open de app een keer met internet.'));
  else { const t = el('div', 'rtext'); t.append(linkify(text || '(geen tekst)')); rb.append(t); }
}
function closeMail() { $('scrim').hidden = true; $('reader').hidden = true; current = null; objectUrls.forEach(u => URL.revokeObjectURL(u)); objectUrls = []; lastFocus?.focus?.(); }
$('rclose').onclick = closeMail; $('scrim').onclick = closeMail;
addEventListener('keydown', e => { if (e.key === 'Escape' && !$('reader').hidden) closeMail(); });

let viewToken = 0;
async function showAttachment(a, view) {
  const token = ++viewToken;
  view.hidden = false; view.textContent = '';
  const bar = el('div', 'attbar'); bar.append(el('span', 'attname', a.name || 'bijlage'));
  const pages = el('div', 'pages'); pages.append(el('p', 'rmeta', 'Bijlage laden…'));
  view.append(bar, pages);
  let blob;
  try {
    const r = await fetch('data/a/' + a.file + '.bin'); if (!r.ok) throw new Error();
    blob = new Blob([await decrypt(KEY, await r.arrayBuffer())], { type: a.type || 'application/octet-stream' });
  } catch { if (token === viewToken) { pages.textContent = ''; pages.append(el('p', 'rmeta', 'Deze bijlage is nog niet op dit toestel opgeslagen. Open de app een keer met internet.')); } return; }
  if (token !== viewToken) return;
  const url = URL.createObjectURL(blob); objectUrls.push(url);
  const save = el('a', 'savebtn', 'Openen'); save.href = url; save.download = a.name || 'bijlage'; save.target = '_blank'; bar.append(save);
  pages.textContent = '';
  if ((a.type || '').startsWith('image/')) { const img = el('img', 'attimg'); img.alt = a.name || ''; img.src = url; pages.append(img); return; }
  if (a.type === 'application/pdf' || /\.pdf$/i.test(a.name || '')) {
    try {
      const lib = window.pdfjsLib; lib.GlobalWorkerOptions.workerSrc = 'vendor/pdf.worker.min.js';
      const pdf = await lib.getDocument({ data: new Uint8Array(await blob.arrayBuffer()) }).promise;
      const w = Math.min(pages.clientWidth || 560, 900);
      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i); if (token !== viewToken) return;
        const vp1 = page.getViewport({ scale: 1 }); const vp = page.getViewport({ scale: (w / vp1.width) * (devicePixelRatio || 1) });
        const c = el('canvas', 'pdfpage'); c.width = vp.width; c.height = vp.height; pages.append(c);
        await page.render({ canvasContext: c.getContext('2d'), viewport: vp }).promise;
      }
    } catch { pages.textContent = ''; pages.append(el('p', 'rmeta', 'Deze PDF kon niet getoond worden. Tik op Openen.')); }
    return;
  }
  pages.append(el('p', 'rmeta', 'Dit soort bestand kan de app niet tonen. Tik op Openen.'));
}

/* ---------- search box ---------- */
let tmr;
$('q').addEventListener('input', e => { clearTimeout(tmr); tmr = setTimeout(() => { state.q = norm(e.target.value.trim()); if (state.q) loadAllBodies(); render(); }, 150); });

/* ---------- boot ---------- */
async function showSetup(dk) {
  $('app').hidden = true; $('setup').hidden = false;
  const code = pairingCode(dk); $('code').textContent = code;
  setStatus('nog niet gekoppeld', navigator.onLine);
  $('copy').onclick = async () => {
    try { await navigator.clipboard.writeText(code); $('copy').textContent = 'Gekopieerd'; }
    catch { const r = document.createRange(); r.selectNodeContents($('code')); const s = getSelection(); s.removeAllRanges(); s.addRange(r); $('copy').textContent = 'Geselecteerd, nu kopiëren'; }
  };
  $('recheck').onclick = () => boot(true);
}
async function boot(force) {
  if (!window.crypto?.subtle || !window.indexedDB) { setStatus('deze browser wordt niet ondersteund', false); return; }
  const dk = await deviceKey();
  try { KEY = await dataKey(dk, force); }
  catch (e) {
    if (e.code === 'unpaired' || e.code === 'nokeys') return showSetup(dk);
    setStatus(navigator.onLine ? 'kon de sleutels niet ophalen' : 'geen internet, en dit toestel is nog niet gekoppeld', false); return;
  }
  try { await loadIndex(); }
  catch (e) {
    // data key may have been replaced: try once more with a fresh key
    if (!force) { await idb.del('datakey'); return boot(true); }
    setStatus(navigator.onLine ? 'kon de mail niet laden' : 'geen internet en nog niks opgeslagen', false); return;
  }
  $('setup').hidden = true; $('app').hidden = false;
  render(); statusLine();
  if (navigator.onLine && !state.fromCache) prefetchAll();
}
addEventListener('online', () => boot());
addEventListener('offline', () => statusLine());
if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').then(() => boot()).catch(() => boot());
else boot();
