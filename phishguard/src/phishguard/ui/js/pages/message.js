/* Page: Message Checker */
mountPage('message-checker.html', 'Message Checker', `<div class="wrap">
 <div class="page-head">
  <h1>Message Checker</h1>
  <p>Got a strange text, email, or chat message? Paste it here and see whether it looks like a scam.</p>
 </div>
</div>
<section class="tool">
 <div class="wrap">
  <div class="checker wide">
   <textarea id="min" maxlength="2000" placeholder="Paste a suspicious SMS, email, or chat message here..." aria-label="Message to analyze"></textarea>
   <div class="msg-err" id="merr" role="alert"></div>
   <div class="row">
    <button class="btn primary" id="mgo" type="button">Analyze Message</button>
    <button class="btn ghost" id="mclear" type="button">Clear</button>
    <span class="grow"></span>
    <span class="count" id="mcount">0 / 2000 characters</span>
   </div>
   <div id="mres"></div>
  </div>
 </div>
</section>`);

/* Wiring for message-checker.html */
const min = $('min');

min.addEventListener('input', () => {
  $('mcount').textContent = min.value.length + ' / 2000 characters';
  min.classList.remove('err'); $('merr').textContent = '';
});

$('mclear').onclick = () => {
  min.value = ''; $('mres').innerHTML = ''; $('merr').textContent = '';
  min.classList.remove('err'); $('mcount').textContent = '0 / 2000 characters'; min.focus();
};

$('mgo').onclick = () => {
  const v = min.value.trim(), e = $('merr');
  e.textContent = ''; $('mres').innerHTML = '';
  if (v.length < 10) {
    e.textContent = v ? 'Add a bit more text. Messages need at least 10 characters.' : 'Paste a message to analyze.';
    min.classList.add('err'); return;
  }
  busy($('mgo'), true);
  setTimeout(() => { render(analyzeMsg(v), $('mres')); busy($('mgo'), false, 'Analyze Message'); }, 1400);
};
