/* URL classifier (heuristic demo). Pure logic, no DOM access. */
const TWO    = new Set(['com.ph','gov.ph','edu.ph','org.ph','co.uk']);
const BRANDS = ['paypal','gcash','maya','bdo','bpi','metrobank','facebook','google','microsoft','apple','amazon','netflix','lazada','shopee','dhl','lbc'];
const SHORT  = ['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cutt.ly','rb.gy'];
const BADTLD = ['zip','xyz','top','tk','ml','ga','cf','gq','click','work','support','icu'];
const KEYS   = ['login','verify','secure','update','account','confirm','signin','password','bank','wallet','claim','reward','suspend'];

function regDomain(h) {
  const p = h.split('.');
  if (p.length < 2) return h;
  const l2 = p.slice(-2).join('.');
  return (TWO.has(l2) && p.length >= 3) ? p.slice(-3).join('.') : l2;
}

function analyzeUrl(raw) {
  let u;
  try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : 'http://' + raw); } catch (e) { return null; }
  const host = u.hostname.toLowerCase();
  if (!host || !host.includes('.') && !/^\[/.test(host)) return null;
  const reg = regDomain(host), full = raw.toLowerCase(), tld = host.split('.').pop(), why = [];
  let s = 0;
  const add = (n, t) => { s += n; why.push(t); };

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add(30, 'Uses an IP address instead of a domain name');
  if (u.protocol !== 'https:') add(15, 'Connection is not encrypted (no HTTPS)');
  if (u.username || raw.includes('@')) add(25, 'Contains “@”, which can hide the real destination');
  if (raw.length > 75) add(10, 'Unusually long URL (' + raw.length + ' characters)');
  const hy = (host.match(/-/g) || []).length; if (hy >= 2) add(15, 'Many hyphens in the domain name (' + hy + ')');
  if (host.split('.').length > 4) add(15, 'Too many subdomains');
  if (host.startsWith('xn--') || host.includes('.xn--')) add(20, 'Uses look-alike (punycode) characters');
  if (SHORT.includes(host)) add(20, 'Link shortener hides the final destination');
  if (BADTLD.includes(tld)) add(15, 'Uses a domain ending (.' + tld + ') often seen in scams');
  const kw = KEYS.filter(k => full.includes(k)); if (kw.length >= 2) add(15, 'Contains sensitive words: ' + kw.slice(0, 4).join(', '));
  const br = BRANDS.find(b => host.includes(b) && !reg.startsWith(b + '.')); if (br) add(30, 'Mentions “' + br + '” but is not the official ' + br + ' domain');
  if ((u.search.match(/=/g) || []).length >= 4) add(8, 'Many query parameters');

  s = Math.min(98, s);
  const level = s >= 55 ? 'bad' : s >= 25 ? 'warn' : 'safe';
  if (!why.length) why.push('No suspicious patterns found in the address');
  return {
    type: 'url', input: raw, host: reg, score: Math.max(s, 3), level,
    conf: Math.min(96, 70 + Math.abs(s - 40) / 2 + (why.length > 2 ? 5 : 0) | 0), why
  };
}
