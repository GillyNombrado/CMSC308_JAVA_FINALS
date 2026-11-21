# Hybrid Phishing URL and Scam Message Classifier

Plain HTML + JavaScript front end. No build step: open `index.html`.
Each HTML file is a small shell (`<div id="app">`); JavaScript renders the page.

```
phishing-classifier/
├── index.html / url-checker.html / message-checker.html / about.html
├── css/styles.css
└── js/
    ├── common.js               helpers + result rendering
    ├── layout.js               header, footer, mountPage()
    ├── url-classifier.js       URL detection rules
    ├── message-classifier.js   scam message rules
    └── pages/
        ├── home.js   url.js   message.js   about.js
```
