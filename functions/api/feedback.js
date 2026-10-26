// Pages Function: /api/feedback — stores /preview feedback in its own D1 database.
// POST {name?, message, page?, website?(honeypot)} -> {ok}
// GET  with the read token -> recent feedback as JSON.
//
// Storage: binding FEEDBACK_DB = D1 database "vibecodigital-site-feedback" (this site's
// own database; it is NOT bound to vibeco-flow's — POAM-030).
// Read token: Pages secret FEEDBACK_READ_TOKEN. Never put a token in this file (the repo is
// public). If the secret is missing, every read is refused (fail closed).
// Visitor IP addresses are not stored.

const json = (o, status = 200, extra = {}) =>
  new Response(JSON.stringify(o, null, 2), {
    status,
    headers: { "content-type": "application/json", ...extra },
  });

async function ensure(db) {
  await db.exec(
    "CREATE TABLE IF NOT EXISTS preview_feedback (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "name TEXT, message TEXT NOT NULL, page TEXT, ua TEXT, " +
      "ts TEXT DEFAULT (datetime('now')))"
  );
}

// Constant-time comparison of two strings via their SHA-256 digests.
async function sameSecret(given, expected) {
  if (typeof given !== "string" || typeof expected !== "string" || !given || !expected) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export async function onRequestPost({ request, env }) {
  const cors = { "access-control-allow-origin": "*" };
  try {
    const db = env.FEEDBACK_DB;
    if (!db) return json({ ok: false, error: "storage-unavailable" }, 500, cors);
    const b = await request.json().catch(() => ({}));
    if (b.website) return json({ ok: true }, 200, cors); // honeypot: silently drop bots
    const message = (b.message || "").toString().trim();
    const name = (b.name || "").toString().trim().slice(0, 80);
    const page = (b.page || "").toString().slice(0, 300);
    if (message.length < 2 || message.length > 4000)
      return json({ ok: false, error: "Please enter a comment (2–4000 characters)." }, 400, cors);
    await ensure(db);
    const ua = (request.headers.get("user-agent") || "").slice(0, 300);
    await db
      .prepare("INSERT INTO preview_feedback (name, message, page, ua) VALUES (?, ?, ?, ?)")
      .bind(name || null, message, page, ua)
      .run();
    return json({ ok: true }, 200, cors);
  } catch (e) {
    return json({ ok: false, error: "server-error" }, 500, cors);
  }
}

export async function onRequestGet({ request, env }) {
  const noStore = { "cache-control": "no-store" };
  const url = new URL(request.url);
  const auth = request.headers.get("authorization") || "";
  const given = auth.startsWith("Bearer ") ? auth.slice(7).trim() : url.searchParams.get("token");
  if (!(await sameSecret(given, env.FEEDBACK_READ_TOKEN)))
    return json({ ok: false, error: "unauthorized" }, 401, noStore);
  const db = env.FEEDBACK_DB;
  if (!db) return json({ ok: false, error: "storage-unavailable" }, 500, noStore);
  await ensure(db);
  const { results } = await db
    .prepare("SELECT id, name, message, page, ts FROM preview_feedback ORDER BY id DESC LIMIT 300")
    .all();
  return json({ ok: true, count: results.length, feedback: results }, 200, noStore);
}
