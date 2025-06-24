# Solution

Need to go into more detail when I get time but:

* Abuse the grandparent-child SOP relationship to override a child frame on the page.
* Exhaust the Chrome Connection pool to create a race window to override the child iframe (and consequently block the loading of ad.js which removes it).
* Bypass the postMessage origin check
* XSS -> proxy XSS to analytics service -> postMessage -> exfil cookies


