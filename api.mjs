// Netlify Function v2. Simpan di repo sebagai: netlify/functions/api.mjs
// Env di Netlify: ADMIN_PASSWORD (wajib), AUTH_SECRET (opsional, teks acak panjang)
import { getStore } from "@netlify/blobs";

const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const same = (a, b) => a.length === b.length && [...a].reduce((r, c, i) => r | (c.charCodeAt(0) ^ b.charCodeAt(i)), 0) === 0;
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

async function sign(msg) {
  const E = process.env;
  const key = await crypto.subtle.importKey("raw", enc.encode(E.AUTH_SECRET || E.ADMIN_PASSWORD), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}

export default async (req) => {
  const E = process.env;
  if (!E.ADMIN_PASSWORD) return json({ error: "ADMIN_PASSWORD belum diisi di Netlify" }, 500);
  const path = new URL(req.url).pathname.replace(/^\/api\/?/, "");

  if (path === "login" && req.method === "POST") {
    const { password = "" } = await req.json().catch(() => ({}));
    await new Promise((r) => setTimeout(r, 600));
    if (!same(String(password), E.ADMIN_PASSWORD)) return json({ error: "Password salah" }, 401);
    const exp = Date.now() + 30 * 864e5;
    return json({ token: exp + "." + (await sign(String(exp))) });
  }

  const [exp, sig] = (req.headers.get("authorization") || "").replace("Bearer ", "").split(".");
  if (!exp || !sig || +exp < Date.now() || !same(sig, await sign(exp))) return json({ error: "Belum login" }, 401);

  if (path === "db") {
    const store = getStore("lyra");
    if (req.method === "GET") return json((await store.get("db", { type: "json" })) || {});
    if (req.method === "PUT") {
      const body = await req.json().catch(() => null);
      if (!body || typeof body !== "object") return json({ error: "Data tidak valid" }, 400);
      await store.setJSON("db", body);
      return json({ ok: true });
    }
  }
  return json({ error: "Tidak ditemukan" }, 404);
};

export const config = { path: "/api/*" };
