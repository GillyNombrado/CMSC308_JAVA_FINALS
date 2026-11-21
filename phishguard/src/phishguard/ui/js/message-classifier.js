/* Scam message classifier (heuristic demo). Needs url-classifier.js loaded first. */
const RULES = [
  [/urgent|immediately|within \d+ ?(hours?|hrs?|minutes?)|act now|last chance|final notice|expires? (today|soon)|asap/i, 18, 'Urgency or pressure to act quickly'],
  [/gift ?card|wire transfer|western union|bitcoin|crypto|send (money|payment)|gcash|processing fee|pay(ment)? (now|required)|deposit/i, 22, 'Suspicious payment request'],
  [/otp|password|pin\b|cvv|card number|ssn|social security|verify your (account|identity)|login details|account number/i, 25, 'Asks for sensitive information'],
  [/(your|account).{0,25}(suspended|locked|blocked|compromised|deactivated|limited)/i, 20, 'Claims your account has a problem'],
  [/bank|paypal|gcash|maya|dhl|lbc|fedex|irs|police|government|customer (support|service)|microsoft|apple|amazon/i, 10, 'Possible impersonation of a trusted organization'],
  [/you(?:'ve| have)? won|winner|prize|lottery|congratulations|claim your|free (iphone|money|reward)|inheritance|guaranteed (income|return)/i, 22, 'Too-good-to-be-true offer or prize'],
  [/do not (tell|share)|keep (this )?(secret|confidential)/i, 10, 'Asks for secrecy'],
  [/dear (customer|user|client|sir\/madam)/i, 6, 'Generic greeting instead of your name']
];

function analyzeMsg(raw) {
  const why = []; let s = 0;
  RULES.forEach(([re, n, t]) => { if (re.test(raw)) { s += n; why.push(t); } });

  const urls = raw.match(/(?:https?:\/\/|www\.)[^\s]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|ph|xyz|top|click|zip|info|biz|ly|co)\b[^\s]*/gi) || [];
  let worst = 0;
  urls.forEach(x => { const r = analyzeUrl(x.replace(/[.,;)]+$/, '')); if (r) worst = Math.max(worst, r.score); });
  if (urls.length) {
    const add = worst >= 25 ? 20 : 8;
    s += add;
    why.push(worst >= 25 ? 'Contains a suspicious link (' + urls[0].slice(0, 40) + ')' : 'Contains a link, so check it with the URL Checker');
  }
  if (/!{2,}|[A-Z]{6,}.*[A-Z]{6,}/.test(raw)) s += 5, why.push('Excessive capital letters or exclamation marks');

  s = Math.min(98, s);
  const level = s >= 55 ? 'bad' : s >= 25 ? 'warn' : 'safe';
  if (!why.length) why.push('No common scam patterns found');
  return { type: 'msg', input: raw, score: Math.max(s, 3), level, conf: Math.min(95, 68 + Math.abs(s - 40) / 2 | 0), why };
}
