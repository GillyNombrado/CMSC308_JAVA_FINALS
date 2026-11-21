/* Shared layout: renders header + footer around each page's content */
const SITE_TITLE = 'Hybrid Phishing URL and Scam Message Classifier';
const NAV = [
  ['index.html', 'Home'],
  ['url-checker.html', 'URL Checker'],
  ['message-checker.html', 'Message Checker'],
  ['about.html', 'About Us']
];
const LOGO = `<svg width="34" height="34" viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.4 9.4-8 11-4.6-1.6-8-6-8-11V5l8-3z" fill="#e91e8c"/><path d="M8.5 12l2.5 2.5 4.5-5" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function headerHtml(active) {
  const links = NAV.map(([href, label]) =>
    `<a href="${href}"${href === active ? ' class="on" aria-current="page"' : ''}>${label}</a>`).join('');
  return `<header>
 <div class="wrap bar">
  <a class="brand" href="index.html">${LOGO}<span>${SITE_TITLE}</span></a>
  <button class="menu" id="menu" aria-label="Toggle menu" aria-expanded="false">Menu</button>
  <nav id="nav">${links}</nav>
 </div>
</header>`;
}

function footerHtml() {
  return `<footer>
 <div class="wrap">
  <div class="fgrid">
   <div><h5>Hybrid Phishing URL and Scam Message Classifier</h5><p style="margin:0;max-width:340px">An academic project that helps people spot phishing links and scam messages.</p></div>
   <div><h5>Explore</h5><a href="index.html">Home</a><a href="url-checker.html">URL Checker</a><a href="message-checker.html">Message Checker</a><a href="about.html">About Us</a></div>
   <div><h5>Legal</h5><a href="#privacy">Privacy Notice</a><a href="#disclaimer">Disclaimer</a></div>
  </div>
  <div class="disc"><p id="privacy" style="margin:0 0 8px"><b>Privacy Notice:</b> Content you enter is analyzed in your browser and is not stored or sent anywhere.</p><p id="disclaimer" style="margin:0"><b>Disclaimer:</b> This tool is designed to assist in identifying potential online threats. Scan results are not a guarantee that a website or message is safe.</p></div>
 </div>
</footer>`;
}

/* Call once per page: mountPage('about.html', 'About Us', '<section>...</section>') */
function mountPage(active, title, contentHtml) {
  document.title = title === SITE_TITLE ? title : title + ' | ' + SITE_TITLE;
  document.getElementById('app').innerHTML = headerHtml(active) + '<main>' + contentHtml + '</main>' + footerHtml();
  const btn = document.getElementById('menu'), nav = document.getElementById('nav');
  btn.onclick = () => {
    const open = nav.classList.toggle('open');
    btn.setAttribute('aria-expanded', open);
  };
}
