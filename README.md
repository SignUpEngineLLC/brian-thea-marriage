# Brian & Thea

Password-protected pages for planning the marriage, published with GitHub Pages at
https://signupenginellc.github.io/brian-thea-marriage/

Built the same way as SignUpEngine Reports: the readable pages never reach this (public) repo.

## Layout

```
site.json                       the pages, and the sync Worker's URL
build.py                        builds the site: uv run build.py
sync.js                         saves and shares checkboxes and notes (inlined into every page)
<slug>/index.html               one locked page (generated, don't edit)
worker/                         Cloudflare Worker that stores the shared checklist state

_private/                       gitignored, stays on this PC only
  sources/<slug>.html           the original page HTML
  password.json                 {"password", "salt"}
```

## Adding or changing a page

1. Save the HTML as `_private/sources/<slug>.html` and add it to `pages` in `site.json`.
2. Give every checkbox and the notes box a `data-id` (for example `<input type="checkbox" data-id="fees">`).
   Saved checks are stored by `data-id`, so keep an id when you reword its question.
3. Run `uv run build.py`, then commit and push to `main`. Pages redeploys in a minute or two.

## Password protection

`build.py` encrypts each page with AES-256-GCM, using a key derived from the password
(PBKDF2-SHA256, 600,000 iterations). The page decrypts itself in the browser. "Remember on this
device" keeps the key so the page opens without asking again.

## Saved checks

Checking a box or typing notes saves the change on the device and sends it to the Worker
(`https://brian-thea-sync.signupengine-roi-report.workers.dev`, Cloudflare account
"Brian@gutcreative.com's Account"), so everyone with the password sees the same state. The page polls
every 20 seconds and when it comes back into view.

- The state is encrypted in the browser with the page key, so the Worker only stores ciphertext.
- Each change carries its time, and the newer change wins item by item, so two people checking boxes at
  the same time both keep theirs. The Worker refuses a save based on an old version (409), so the
  page merges and tries again.
- Offline changes stay on the device and sync when the connection comes back.
- The Worker only answers requests with a token derived from the page key. It keeps the token's
  SHA-256 hash in the `TOKEN_HASH` secret.

### Changing the password

Changing `password` or `salt` in `_private/password.json` changes the key, so:

1. `uv run build.py`, commit and push.
2. Update the Worker's secret: `uv run build.py --token-hash | (cd worker && npx.cmd wrangler secret put TOKEN_HASH)`.
3. The saved checks were encrypted with the old key and can't be read any more; they start empty.

### Worker

```
cd worker
npm.cmd install
npx.cmd wrangler deploy
```
