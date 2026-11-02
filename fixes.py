# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=42", "requests>=2.31"]
# ///
"""Show the translation fixes (and visit notes) saved on the live page.

    uv run fixes.py

Reads the shared state from the sync Worker and decrypts it with the password in
_private/password.json. Fixes are stored as "tr:<lang>:<key>": <lang> is hil or tl, and <key>
is a checkbox's data-id plus ".q" (question) or ".why" (note), or a block's data-k.
To make a fix permanent, put it into _private/sources/<slug>.html and rebuild; once the
draft matches, the page shows it as the draft and the saved fix no longer matters.
"""

import base64
import json
import sys

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from build import PASSWORD, ROOT, derive_key, sync_token


def main() -> int:
    secret = json.loads(PASSWORD.read_text(encoding="utf-8"))
    key = derive_key(secret["password"], bytes.fromhex(secret["salt"]))
    url = json.loads((ROOT / "site.json").read_text(encoding="utf-8"))["sync_url"]
    res = requests.get(url, headers={"Authorization": "Bearer " + sync_token(key)}, timeout=20)
    res.raise_for_status()
    blob = res.json()["blob"]
    if not blob:
        print("Nothing saved yet.")
        return 0
    plain = AESGCM(key).decrypt(base64.b64decode(blob["i"]), base64.b64decode(blob["d"]), None)
    items = json.loads(plain)["c"]

    fixes = {k: e for k, e in items.items() if k.startswith("tr:") and isinstance(e.get("v"), str) and e["v"].strip()}
    names = {"hil": "Hiligaynon", "tl": "Tagalog"}
    if fixes:
        print(f"{len(fixes)} translation fix(es):\n")
        for k in sorted(fixes):
            _, lang, where = k.split(":", 2)
            print(f"[{names.get(lang, lang)}] {where}\n    {fixes[k]['v']}\n")
    else:
        print("No translation fixes saved.")
    notes = items.get("notes", {}).get("v")
    if isinstance(notes, str) and notes.strip():
        print("Notes from the visit:\n" + notes)
    checked = sorted(k for k, e in items.items() if e.get("v") is True)
    print(f"\nChecked: {', '.join(checked) if checked else 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
