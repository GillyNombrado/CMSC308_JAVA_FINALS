/* Shared helpers: DOM, menu toggle, result rendering */
const $ = id => document.getElementById(id);
const esc = s => s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ts = () => new Date().toLocaleString();

/* ---------- Result rendering ---------- */
const S = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">';
const IC_OK   = S + '<path d="M12 3l8 3v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>';
const IC_WARN = S + '<path d="M12 4L3 20h18L12 4z"/><path d="M12 10v4M12 17.5v.01"/></svg>';
const IC_BAD  = S + '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5M12 16v.01"/></svg>';

const COPY = {
  url: {
    safe: [IC_OK,   'Potentially Safe',            'No significant phishing indicators were detected.', 'SAFE'],
    warn: [IC_WARN, 'Suspicious Link',             'This URL contains patterns that may indicate a potential threat.', 'SUSPICIOUS'],
    bad:  [IC_BAD,  'Potential Phishing Detected', 'This URL shows indicators commonly associated with phishing attempts.', 'PHISHING']
  },
  msg: {
    safe: [IC_OK,   'Looks Legitimate',  'No common scam patterns were detected in this message.', 'LEGITIMATE'],
    warn: [IC_WARN, 'Suspicious Message','This message contains patterns that are often used in scams.', 'SUSPICIOUS'],
    bad:  [IC_BAD,  'Likely a Scam',     'This message shows several indicators commonly found in scam attempts.', 'SCAM']
  }
};

function render(r, el) {
  const [ico, title, desc, label] = COPY[r.type][r.level];
  const lv = r.score >= 55 ? 'High' : r.score >= 25 ? 'Medium' : 'Low';
  const shown = r.type === 'url' ? r.input : (r.input.length > 160 ? r.input.slice(0, 160) + '…' : r.input);
  el.innerHTML = `<div class="result ${r.level}" role="status">
  <div class="rhead"><div class="ico">${ico}</div><div><h3>${title}</h3><p>${desc}</p></div></div>
  <div class="url">${esc(shown)}</div>
  <div class="stats">
   <div class="stat"><span>Status</span><b>${label}</b></div>
   <div class="stat"><span>Risk level: ${lv}</span><b>${r.score}%</b><div class="meter"><i id="mt"></i></div></div>
   <div class="stat"><span>Confidence</span><b>${r.conf}%</b></div>
  </div>
  <h4>Why we think so</h4>
  <ul>${r.why.map(w => '<li>' + esc(w) + '</li>').join('')}</ul>
  <div class="time">Scanned ${ts()}${r.level === 'safe' ? ' · A low score does not guarantee safety. Stay cautious.' : ''}</div></div>`;
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const m = el.querySelector('#mt');
    if (m) m.style.width = r.score + '%';
  }));
}

function busy(btn, on, txt) {
  btn.disabled = on;
  btn.innerHTML = on ? '<span class="spin"></span> Scanning…' : txt;
}
