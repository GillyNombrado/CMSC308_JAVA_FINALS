/* Page: URL Checker */
mountPage('url-checker.html', 'URL Checker', `<div class="wrap">
 <div class="page-head">
  <h1>URL Checker</h1>
  <p>Paste a suspicious link to see whether the website looks like phishing.</p>
 </div>
</div>
<section class="tool">
 <div class="wrap">
  <div class="checker">
   <div class="field" id="ufield">
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#b07a9a" stroke-width="2" stroke-linecap="round"><path d="M10 14a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1"/><path d="M14 10a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1"/></svg>
    <input id="uin" type="text" inputmode="url" autocomplete="off" spellcheck="false" placeholder="Paste a suspicious link here..." aria-label="URL to check">
    <button class="btn ghost" id="upaste" type="button">Paste</button>
    <button class="btn ghost" id="uclear" type="button">Clear</button>
    <button class="btn primary" id="ugo" type="button">Check URL</button>
   </div>
   <div class="msg-err" id="uerr" role="alert"></div>
   <div id="ures"></div>
  </div>
 </div>
</section>`);

/* Wiring for url-checker.html */
const uin = $('uin');

$('upaste').onclick = async () => {
  try { uin.value = await navigator.clipboard.readText(); uin.focus(); }
  catch (e) { $('uerr').textContent = 'Clipboard access was blocked. Paste with Ctrl+V or ⌘V instead.'; }
};

$('uclear').onclick = () => {
  uin.value = ''; $('ures').innerHTML = ''; $('uerr').textContent = '';
  $('ufield').classList.remove('err'); uin.focus();
};

function checkUrl() {
  const v = uin.value.trim(), f = $('ufield'), e = $('uerr');
  e.textContent = ''; f.classList.remove('err'); $('ures').innerHTML = '';
  if (!v) { e.textContent = 'Enter a link to check.'; f.classList.add('err'); return; }
  if (/\s/.test(v) || v.length > 2048) { e.textContent = 'That doesn’t look like a single link. Remove spaces and try again.'; f.classList.add('err'); return; }
  const r = analyzeUrl(v);
  if (!r) { e.textContent = 'We couldn’t read that as a link. Try something like example.com/page.'; f.classList.add('err'); return; }
  busy($('ugo'), true);
  setTimeout(() => { render(r, $('ures')); busy($('ugo'), false, 'Check URL'); }, 1200);
}

$('ugo').onclick = checkUrl;
uin.addEventListener('keydown', e => { if (e.key === 'Enter') checkUrl(); });
