// Pages Function: /api/feedback — stores preview feedback in an isolated D1 table.
// POST {name?, message, page?, website?(honeypot)} -> {ok}
// GET  ?token=... -> recent feedback as JSON (soft read gate)

const READ_TOKEN = "vc-fb-7q2m9x4k8w";

const json = (o, status = 200) =>
  new Response(JSON.stringify(o, null, 2), {
    status,
    headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
  });

async function ensure(db) {
  await db.exec(
    "CREATE TABLE IF NOT EXISTS preview_feedback (" +
      "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
      "name TEXT, message TEXT NOT NULL, page TEXT, ua TEXT, ip TEXT, " +
      "ts TEXT DEFAULT (datetime('now')))"
  );
}

export async function onRequestPost({ request, env }) {
  try {
    const db = env.FEEDBACK_DB;
    if (!db) return json({ ok: false, error: "storage-unavailable" }, 500);
    const b = await request.json().catch(() => ({}));
    if (b.website) return json({ ok: true }); // honeypot: silently drop bots
    const message = (b.message || "").toString().trim();
    const name = (b.name || "").toString().trim().slice(0, 80);
    const page = (b.page || "").toString().slice(0, 300);
    if (message.length < 2 || message.length > 4000)
      return json({ ok: false, error: "Please enter a comment (2–4000 characters)." }, 400);
    await ensure(db);
    const ua = (request.headers.get("user-agent") || "").slice(0, 300);
    const ip = request.headers.get("cf-connecting-ip") || "";
    await db
      .prepare("INSERT INTO preview_feedback (name, message, page, ua, ip) VALUES (?, ?, ?, ?, ?)")
      .bind(name || null, message, page, ua, ip)
      .run();
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: String(e && e.message ? e.message : e).slice(0, 200) }, 500);
  }
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  if (url.searchParams.get("token") !== READ_TOKEN)
    return json({ ok: false, error: "unauthorized" }, 401);
  const db = env.FEEDBACK_DB;
  if (!db) return json({ ok: false, error: "storage-unavailable" }, 500);
  await ensure(db);
  const { results } = await db
    .prepare("SELECT id, name, message, page, ts FROM preview_feedback ORDER BY id DESC LIMIT 300")
    .all();
  return json({ ok: true, count: results.length, feedback: results });
}
