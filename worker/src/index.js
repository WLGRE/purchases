// Receipt worker: stores receipt files in R2 and reads them with Claude.
//
// /upload, /sign and /scan need a signed-in Supabase user (Authorization: Bearer <access token>),
// and each user can only reach files in their own folder: "<user id>/...".
// /file serves a receipt from a short-lived signed link made by /sign, because <img> tags and
// new tabs can't send the Authorization header.
import Anthropic from "@anthropic-ai/sdk";

const MAX_UPLOAD = 10 * 1024 * 1024; // 10 MB
const MAX_SCAN_IMAGE = 5 * 1024 * 1024; // Claude's per-image limit
const LINK_TTL = 10 * 60; // seconds a view link stays valid
const TYPES = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif", "application/pdf": "pdf" };
const DEFAULT_CATEGORIES = ["Office Supplies", "Food", "Equipment", "Materials", "Maintenance", "Utilities", "Travel", "Meals", "Software", "Other"];

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

export default {
  async fetch(req, env) {
    const cors = corsHeaders(req, env);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    const url = new URL(req.url);
    try {
      if (url.pathname === "/file" && req.method === "GET") return await serveFile(url, env);
      const user = await getUser(req, env);
      if (!user) throw new HttpError(401, "Sign in required");
      if (url.pathname === "/upload" && req.method === "POST") return json(await upload(req, env, user), 200, cors);
      if (url.pathname === "/sign" && req.method === "GET") return json(await sign(url, env, user), 200, cors);
      if (url.pathname === "/scan" && req.method === "POST") return json(await scan(req, env, user), 200, cors);
      throw new HttpError(404, "Not found");
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, e.status, cors);
      console.error(e);
      return json({ error: "Something went wrong" }, 500, cors);
    }
  },
};

function corsHeaders(req, env) {
  const origin = req.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim());
  if (!allowed.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function json(body, status, headers) {
  return new Response(JSON.stringify(body), { status, headers: { ...headers, "Content-Type": "application/json" } });
}

// Asks Supabase who the token belongs to, so the worker never needs the project's signing secret.
async function getUser(req, env) {
  const auth = req.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const res = await fetch(env.SUPABASE_URL + "/auth/v1/user", {
    headers: { Authorization: auth, apikey: env.SUPABASE_ANON_KEY },
  });
  if (!res.ok) return null;
  const user = await res.json();
  return user && user.id ? user : null;
}

function ownKey(user, key) {
  if (typeof key !== "string" || !key.startsWith(user.id + "/")) throw new HttpError(403, "Not your receipt");
  return key;
}

async function upload(req, env, user) {
  const form = await req.formData();
  const file = form.get("file");
  if (!file || typeof file === "string") throw new HttpError(400, "No file attached");
  const ext = TYPES[file.type];
  if (!ext) throw new HttpError(415, "Receipts must be a JPEG, PNG, WebP or GIF photo, or a PDF");
  if (file.size > MAX_UPLOAD) throw new HttpError(413, "Receipts must be 10 MB or smaller");
  // The app reads the file type back from the extension, so the key always ends in the right one.
  const base = (file.name || "receipt").replace(/\.[^.]*$/, "").replace(/[^a-zA-Z0-9_-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "receipt";
  const key = `${user.id}/${Date.now()}-${crypto.randomUUID().slice(0, 8)}-${base}.${ext}`;
  await env.RECEIPTS.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: file.type } });
  return { key };
}

// ── View links ────────────────────────────────────────────────────
async function hmacKey(env) {
  return crypto.subtle.importKey("raw", new TextEncoder().encode(env.LINK_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => /^[0-9a-f]{64}$/.test(hex) ? new Uint8Array(hex.match(/../g).map((h) => parseInt(h, 16))) : null;

async function sign(url, env, user) {
  const key = ownKey(user, url.searchParams.get("key"));
  const exp = Math.floor(Date.now() / 1000) + LINK_TTL;
  const sig = toHex(await crypto.subtle.sign("HMAC", await hmacKey(env), new TextEncoder().encode(key + "\n" + exp)));
  const link = new URL("/file", url.origin);
  link.search = new URLSearchParams({ key, exp: String(exp), sig }).toString();
  return { url: link.toString() };
}

async function serveFile(url, env) {
  const key = url.searchParams.get("key") || "";
  const exp = Number(url.searchParams.get("exp"));
  const sig = fromHex(url.searchParams.get("sig") || "");
  if (!sig || !Number.isFinite(exp) || exp < Date.now() / 1000) throw new HttpError(403, "This link has expired");
  // crypto.subtle.verify compares in constant time.
  const valid = await crypto.subtle.verify("HMAC", await hmacKey(env), sig, new TextEncoder().encode(key + "\n" + exp));
  if (!valid) throw new HttpError(403, "This link has expired");
  const obj = await env.RECEIPTS.get(key);
  if (!obj) throw new HttpError(404, "Receipt not found");
  return new Response(obj.body, {
    headers: {
      "Content-Type": obj.httpMetadata?.contentType || "application/octet-stream",
      "Content-Disposition": "inline",
      "Cache-Control": "private, max-age=600",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

// ── AI scan ───────────────────────────────────────────────────────
async function scan(req, env, user) {
  const body = await req.json().catch(() => ({}));
  const key = ownKey(user, body.key);
  const today = /^\d{4}-\d{2}-\d{2}$/.test(body.today || "") ? body.today : new Date().toISOString().slice(0, 10);
  const categories = Array.isArray(body.categories) && body.categories.length
    ? body.categories.filter((c) => typeof c === "string" && c.length <= 40).slice(0, 30)
    : DEFAULT_CATEGORIES;

  const obj = await env.RECEIPTS.get(key);
  if (!obj) throw new HttpError(404, "Receipt not found");
  const type = obj.httpMetadata?.contentType || "";
  if (!TYPES[type]) throw new HttpError(415, "This file type can't be scanned");
  const bytes = await obj.arrayBuffer();
  if (type !== "application/pdf" && bytes.byteLength > MAX_SCAN_IMAGE) throw new HttpError(413, "This photo is too large to scan");
  const data = Buffer.from(bytes).toString("base64");
  const receipt = type === "application/pdf"
    ? { type: "document", source: { type: "base64", media_type: type, data } }
    : { type: "image", source: { type: "base64", media_type: type, data } };

  const schema = {
    type: "object",
    properties: {
      store: { type: "string" },
      receiptNum: { type: "string" },
      date: { type: "string" },
      amount: { type: "number" },
      category: { type: "string", enum: categories },
      notes: { type: "string" },
    },
    required: ["store", "receiptNum", "date", "amount", "category", "notes"],
    additionalProperties: false,
  };
  const prompt = `This is a receipt for a business purchase. Pull out these details:
- store: the store or business name as printed.
- receiptNum: the receipt, transaction or order number, or "" if there isn't one.
- date: the purchase date as YYYY-MM-DD. If no date is printed, use ${today}.
- amount: the final total paid, as a plain number with no currency sign.
- category: the closest fit from the allowed list.
- notes: one short sentence saying what was bought.
If a detail can't be read, use "" (or 0 for amount) rather than guessing.`;

  const client = new Anthropic({ apiKey: env.ANTHROPIC_API_KEY });
  let response;
  try {
    response = await client.beta.messages.create({
      model: "claude-opus-5-5",
      max_tokens: 16000,
      // If a safety check declines the request, Anthropic retries it on its recommended fallback model.
      betas: ["server-side-fallback-2026-07-01"],
      fallbacks: "default",
      output_config: { effort: "low", format: { type: "json_schema", schema } },
      messages: [{ role: "user", content: [receipt, { type: "text", text: prompt }] }],
    });
  } catch (e) {
    if (e instanceof Anthropic.RateLimitError) throw new HttpError(429, "The AI scanner is busy. Try again in a minute");
    if (e instanceof Anthropic.AuthenticationError) { console.error("Claude rejected ANTHROPIC_API_KEY"); throw new HttpError(503, "AI scan isn't set up"); }
    if (e instanceof Anthropic.BadRequestError) { console.error("Claude bad request:", e.message); throw new HttpError(422, "This receipt couldn't be read"); }
    if (e instanceof Anthropic.APIError) { console.error(`Claude API error ${e.status}:`, e.message); throw new HttpError(502, "AI scan is unavailable right now"); }
    throw e;
  }
  if (response.stop_reason === "refusal" || response.stop_reason === "max_tokens") throw new HttpError(422, "This receipt couldn't be read");
  const text = response.content.find((b) => b.type === "text")?.text;
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(422, "This receipt couldn't be read");
  }
}
