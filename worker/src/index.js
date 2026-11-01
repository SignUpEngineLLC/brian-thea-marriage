// Stores the checklist state for the site, so both phones see the same checks and notes.
//
// The state arrives already encrypted with the key derived from the site password, so this
// Worker only ever holds ciphertext. Requests must carry a token that is also derived from
// that key (SHA-256 of "btm-sync|" + key); the Worker keeps only the token's SHA-256 hash,
// in the TOKEN_HASH secret. It cannot work out the key or the password from either.
//
//   GET /state  -> {v, blob}           v counts saves; blob is null until the first save
//   PUT /state  {v, blob} -> {v}       v must match the stored v, else 409 with the current {v, blob}

const MAX_BODY = 256 * 1024;

// One instance holds the state, so every save is checked against the latest version.
export class SyncState {
  constructor(ctx) {
    this.storage = ctx.storage;
  }

  async fetch(request) {
    // Input gates keep other requests out between this get and put.
    const current = (await this.storage.get("state")) || { v: 0, blob: null };
    if (request.method === "GET") return Response.json(current);

    const body = await request.json();
    if (body.v !== current.v) return Response.json(current, { status: 409 });
    const next = { v: current.v + 1, blob: body.blob };
    await this.storage.put("state", next);
    return Response.json({ v: next.v });
  }
}

async function sha256hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sameString(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function validBlob(blob) {
  return blob && typeof blob === "object" && typeof blob.i === "string" && typeof blob.d === "string";
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowed = env.ALLOWED_ORIGINS.split(",").map((s) => s.trim());
    const headers = { Vary: "Origin", "Cache-Control": "no-store" };
    if (allowed.includes(origin)) {
      Object.assign(headers, {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
        "Access-Control-Max-Age": "86400",
      });
    }
    const reply = (body, status) =>
      new Response(typeof body === "string" ? body : JSON.stringify(body), {
        status,
        headers: { ...headers, "Content-Type": typeof body === "string" ? "text/plain" : "application/json" },
      });

    if (new URL(request.url).pathname !== "/state") return reply("Not found", 404);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers });
    if (request.method !== "GET" && request.method !== "PUT") return reply("Method not allowed", 405);

    const auth = request.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!env.TOKEN_HASH || !token || !sameString(await sha256hex(token), env.TOKEN_HASH)) {
      return reply("Unauthorized", 401);
    }

    const stub = env.STATE.get(env.STATE.idFromName("main"));
    if (request.method === "GET") {
      const res = await stub.fetch("https://state/", { method: "GET" });
      return reply(await res.json(), res.status);
    }

    const text = await request.text();
    if (text.length > MAX_BODY) return reply("Too large", 413);
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      return reply("Bad JSON", 400);
    }
    if (!Number.isInteger(body.v) || body.v < 0 || !validBlob(body.blob)) return reply("Bad request", 400);

    const res = await stub.fetch("https://state/", {
      method: "PUT",
      body: JSON.stringify({ v: body.v, blob: { i: body.blob.i, d: body.blob.d } }),
    });
    return reply(await res.json(), res.status);
  },
};
