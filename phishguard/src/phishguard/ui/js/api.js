/* Talks to the Java server (WebServer.java). Start it with: java -cp out phishguard.ui.WebServer */
const API_BASE = location.protocol === 'file:' || location.port !== '8080' ? 'http://localhost:8080' : '';

const LEVEL_MAP = { Low: 'safe', Medium: 'warn', High: 'bad' };

/* Finds the first link inside a pasted message, or '' if there is none */
function extractLink(text) {
  const m = text.match(/(?:https?:\/\/|www\.)[^\s]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|ph|xyz|top|click|zip|info|biz|ly|co)\b[^\s]*/i);
  return m ? m[0].replace(/[.,;)!?]+$/, '') : '';
}

/* Sends a link, a message, or both. Resolves to a result object that render() understands. */
async function analyzeRemote(type, url, message) {
  let res;
  try {
    res = await fetch(API_BASE + '/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url || '', message: message || '' })
    });
  } catch (e) {
    throw new Error('Could not reach the PhishGuard server. Make sure it is running (java -cp out phishguard.ui.WebServer) and open this page at http://localhost:8080.');
  }
  let d = null;
  try { d = await res.json(); } catch (e) { /* not JSON */ }
  if (!res.ok) throw new Error((d && d.error) || 'The server returned an error (' + res.status + ').');
  return {
    type, input: type === 'url' ? url : message,
    level: LEVEL_MAP[d.level] || 'safe', levelName: d.level,
    score: d.score, urlScore: d.urlScore, textScore: d.textScore,
    advice: d.advice, why: d.reasons || []
  };
}
