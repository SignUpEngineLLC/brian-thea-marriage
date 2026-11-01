# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42"]
# ///
"""Build the published site from _private/sources/ and site.json.

    uv run build.py                 build every page
    uv run build.py --token-hash    print the TOKEN_HASH secret for the sync Worker

For every page in site.json:
  _private/sources/<slug>.html  ->  <slug>/index.html
sync.js is inlined into the page (so checkboxes and notes are saved and shared), then the
page is AES-256-GCM encrypted with a key derived from the password in
_private/password.json (PBKDF2-SHA256). Only the password page and ciphertext are published.

_private/ is gitignored: it never leaves this PC. Same scheme as SignUpEngine Reports.
"""

import base64
import hashlib
import html
import json
import re
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "_private"
SOURCES = PRIVATE / "sources"
PASSWORD = PRIVATE / "password.json"
ITERATIONS = 600_000
NOINDEX = '<meta name="robots" content="noindex, nofollow">'
LOCK_MARKER = "<!-- brian-thea-marriage:locked -->"


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def sync_token(key: bytes) -> str:
    # Must match tokenP in sync.js.
    return hashlib.sha256(b"btm-sync|" + key).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def add_noindex(page: str) -> str:
    if 'name="robots"' in page:
        return page
    return re.sub(r"(<meta charset[^>]*>)", r"\1\n" + NOINDEX, page, count=1, flags=re.I)


def add_sync(page: str, sync_url: str) -> str:
    script = (ROOT / "sync.js").read_text(encoding="utf-8").replace("{{SYNC_URL}}", sync_url)
    if "</body>" not in page:
        raise ValueError("page has no </body>")
    head, tail = page.rsplit("</body>", 1)
    return f"{head}<script>\n{script}</script>\n</body>{tail}"


def lock_page(page: str, site: str, title: str, key: bytes, salt: bytes) -> str:
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, page.encode("utf-8"), None)
    payload = json.dumps({"s": b64(salt), "i": b64(iv), "n": ITERATIONS, "d": b64(ct)})
    return (
        LOCK_TEMPLATE.replace("{{MARKER}}", LOCK_MARKER)
        .replace("{{NOINDEX}}", NOINDEX)
        .replace("{{SITE}}", html.escape(site))
        .replace("{{TITLE}}", html.escape(title))
        .replace("{{PAYLOAD}}", payload)
    )


def main() -> int:
    config = json.loads((ROOT / "site.json").read_text(encoding="utf-8"))
    secret = json.loads(PASSWORD.read_text(encoding="utf-8"))
    salt = bytes.fromhex(secret["salt"])
    key = derive_key(secret["password"], salt)

    if "--token-hash" in sys.argv:
        print(hashlib.sha256(sync_token(key).encode("ascii")).hexdigest())
        return 0

    errors = []
    for p in config["pages"]:
        src = SOURCES / f'{p["slug"]}.html'
        out = ROOT / p["slug"] / "index.html"
        if not src.exists():
            errors.append(f"missing source: {src.relative_to(ROOT)}")
            continue
        page = add_sync(add_noindex(src.read_text(encoding="utf-8")), config["sync_url"])
        result = lock_page(page, config["name"], p["title"], key, salt)
        # The page's own text must never appear in the locked output.
        body = re.sub(r"<[^>]+>", " ", page.split("<body", 1)[-1])
        probe = max(re.findall(r"[A-Za-z][^<>\n]{40,}", body) or [""], key=len)[:40]
        if LOCK_MARKER not in result or (probe and probe in result):
            errors.append(f"{p['slug']}: locked output failed the plaintext check, not written")
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(result, encoding="utf-8", newline="\n")
        print(f"  locked  {p['slug']}/")

    items = "\n".join(
        f'    <li><a href="{html.escape(p["slug"])}/">{html.escape(p["title"])}</a></li>' for p in config["pages"]
    )
    (ROOT / "index.html").write_text(
        INDEX_TEMPLATE.replace("{{SITE}}", html.escape(config["name"])).replace("{{ITEMS}}", items),
        encoding="utf-8",
        newline="\n",
    )

    if errors:
        print("\nErrors:", *errors, sep="\n  ", file=sys.stderr)
        return 1
    print("Build OK.")
    return 0


INDEX_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{SITE}}</title>
<style>
  body{margin:0;background:#faf8f5;color:#1f2328;font:17px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif}
  .wrap{max-width:720px;margin:0 auto;padding:48px 16px}
  h1{margin:0 0 20px}
  ul{list-style:none;padding:0;margin:0}
  li{border-top:1px solid #e4e0da;padding:14px 0}
  a{color:#0f6e6e;font-weight:600;text-decoration:none} a:hover{text-decoration:underline}
  @media (prefers-color-scheme: dark){body{background:#16181b;color:#e9eaec} li{border-color:#33373d} a{color:#5fc4bd}}
</style>
</head>
<body>
<div class="wrap">
  <h1>{{SITE}}</h1>
  <ul>
{{ITEMS}}
  </ul>
</div>
</body>
</html>
"""

LOCK_TEMPLATE = """<!DOCTYPE html>
{{MARKER}}
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{NOINDEX}}
<title>{{TITLE}}</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;padding:16px;background:#faf8f5;color:#1f2328;
       font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  form{width:100%;max-width:380px;background:#fff;border:1px solid #e4e0da;border-top:3px solid #0f6e6e;border-radius:12px;padding:28px 24px}
  .who{margin:0;color:#5b6370;font-size:14px}
  h1{font-size:21px;margin:6px 0 20px;line-height:1.25}
  label{display:block;font-size:14px;font-weight:600;margin-bottom:6px}
  input[type=password]{width:100%;font:inherit;font-size:16px;padding:10px 12px;border:1px solid #c9c4bd;border-radius:8px}
  input[type=password]:focus{outline:2px solid #0f6e6e;outline-offset:1px}
  .row{display:flex;align-items:center;gap:6px;margin:12px 0 18px;font-size:14px;color:#5b6370}
  button{width:100%;font:inherit;font-weight:600;font-size:16px;padding:12px;border:0;border-radius:999px;background:#0f6e6e;color:#fff;cursor:pointer}
  button:disabled{opacity:.6;cursor:progress}
  .err{color:#a8412f;font-size:14px;min-height:1.2em;margin:10px 0 0}
</style>
</head>
<body>
<form id="f" autocomplete="off">
  <p class="who">{{SITE}}</p>
  <h1>{{TITLE}}</h1>
  <label for="pw">Password</label>
  <input type="password" id="pw" required autofocus>
  <div class="row"><input type="checkbox" id="rm" checked><label for="rm" style="margin:0;font-weight:400">Remember on this device</label></div>
  <button id="go">Open</button>
  <p class="err" id="err" role="alert"></p>
</form>
<script>
(function(){
  var P = {{PAYLOAD}};
  var KEY = "btm-key";
  function unb64(s){ return Uint8Array.from(atob(s), function(c){ return c.charCodeAt(0); }); }
  function store(kind){ try { return window[kind]; } catch (e) { return null; } }
  async function open(key){
    var buf = await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(P.i)}, key, unb64(P.d));
    var page = new TextDecoder().decode(buf);
    // A remembered key decrypts while this page is still loading; document.open() at that
    // point appends to the lock page instead of replacing it, so wait for load first.
    if (document.readyState !== "complete") {
      await new Promise(function(r){ window.addEventListener("load", r, {once:true}); });
    }
    document.open(); document.write(page); document.close();
  }
  async function derive(pw){
    var base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({name:"PBKDF2", salt:unb64(P.s), iterations:P.n, hash:"SHA-256"},
      base, {name:"AES-GCM", length:256}, true, ["decrypt"]);
  }
  var err = document.getElementById("err"), go = document.getElementById("go");
  if (!window.crypto || !crypto.subtle) { err.textContent = "This browser can't open this page. Try an up-to-date Chrome, Safari or Firefox."; go.disabled = true; return; }
  // The page's save-and-share script reads the key from here (sessionStorage when not remembered).
  var local = store("localStorage"), session = store("sessionStorage");
  var saved = (local && local.getItem(KEY)) || (session && session.getItem(KEY));
  if (saved) {
    crypto.subtle.importKey("raw", unb64(saved), "AES-GCM", false, ["decrypt"]).then(open)
      .catch(function(){ try { local.removeItem(KEY); session.removeItem(KEY); } catch (e) {} });
  }
  document.getElementById("f").addEventListener("submit", async function(ev){
    ev.preventDefault();
    err.textContent = ""; go.disabled = true; go.textContent = "Checking\\u2026";
    try {
      var key = await derive(document.getElementById("pw").value);
      var raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
      try { await crypto.subtle.decrypt({name:"AES-GCM", iv:unb64(P.i)}, key, unb64(P.d)); }
      catch (e) { throw new Error("bad"); }
      var enc = btoa(String.fromCharCode.apply(null, raw));
      try { session.setItem(KEY, enc); } catch (e) {}
      if (document.getElementById("rm").checked) { try { local.setItem(KEY, enc); } catch (e) {} }
      await open(key);
    } catch (e) {
      err.textContent = "That password didn't work. Please try again.";
      go.disabled = false; go.textContent = "Open";
      document.getElementById("pw").select();
    }
  });
})();
</script>
</body>
</html>
"""

if __name__ == "__main__":
    sys.exit(main())
