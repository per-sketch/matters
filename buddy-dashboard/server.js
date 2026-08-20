// Per's Dashboard — server
// Live-fetches Google Calendar, Gmail, Asana and Buddy Analytics on demand.
// Password-gated (single shared password), signed session cookie.
// No database; short in-memory cache so the refresh button is instant to spam.

import express from "express";
import crypto from "node:crypto";

const app = express();
app.use(express.urlencoded({ extended: false }));

// ---------- config ----------
const {
  PORT = 8080,
  BASE_URL, // e.g. https://per-dashboard.onrender.com (no trailing slash)
  DASHBOARD_PASSWORD,
  SESSION_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REFRESH_TOKEN, // obtained once via /auth/google
  ASANA_TOKEN, // personal access token
  ASANA_WORKSPACE = "1208551054165653",
  ASANA_GOALS_PROJECT = "1217560633887654",
  BUDDY_MCP_URL = "https://analytics-web-prod.onrender.com/api/mcp",
  BUDDY_API_KEY,
  MY_EMAILS = "per@matters.inc,per@joinbuddy.co",
  CACHE_SECONDS = "120",
} = process.env;

if (!DASHBOARD_PASSWORD || !SESSION_SECRET) {
  console.error("FATAL: DASHBOARD_PASSWORD and SESSION_SECRET must be set.");
  process.exit(1);
}
const myEmails = MY_EMAILS.split(",").map((s) => s.trim().toLowerCase());

// ---------- tiny signed-cookie session ----------
function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
}
function makeSession() {
  const exp = Date.now() + 30 * 24 * 3600 * 1000; // 30 days
  const payload = `ok.${exp}`;
  return `${payload}.${sign(payload)}`;
}
function checkSession(cookieHeader) {
  const m = /(?:^|;\s*)dash_session=([^;]+)/.exec(cookieHeader || "");
  if (!m) return false;
  const parts = decodeURIComponent(m[1]).split(".");
  if (parts.length !== 3) return false;
  const [ok, exp, sig] = parts;
  const payload = `${ok}.${exp}`;
  if (sign(payload) !== sig) return false;
  return ok === "ok" && Number(exp) > Date.now();
}
function requireAuth(req, res, next) {
  if (checkSession(req.headers.cookie)) return next();
  res.redirect("/login");
}

// constant-time password compare
function passwordOk(pw) {
  const a = Buffer.from(String(pw || ""));
  const b = Buffer.from(DASHBOARD_PASSWORD);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- login ----------
const loginPage = (err = "") => `<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Per — Dashboard</title>
<style>body{font-family:-apple-system,sans-serif;background:#f6f7f9;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
form{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:28px;width:300px}
h1{font-size:16px;margin:0 0 14px}input{width:100%;box-sizing:border-box;padding:9px 10px;border:1px solid #e4e7ec;border-radius:8px;font-size:14px;margin-bottom:10px}
button{width:100%;padding:9px;border:0;border-radius:8px;background:#2f5fd0;color:#fff;font-weight:600;font-size:14px;cursor:pointer}
.err{color:#b3352b;font-size:12.5px;margin-bottom:8px}</style></head><body>
<form method="post" action="/login"><h1>Per — Dashboard</h1>${err ? `<div class="err">${err}</div>` : ""}
<input type="password" name="password" placeholder="Password" autofocus>
<button>Sign in</button></form></body></html>`;

app.get("/login", (req, res) => res.send(loginPage()));
app.post("/login", (req, res) => {
  if (passwordOk(req.body.password)) {
    res.setHeader(
      "Set-Cookie",
      `dash_session=${encodeURIComponent(makeSession())}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 3600}`
    );
    return res.redirect("/");
  }
  res.status(401).send(loginPage("Wrong password."));
});

// ---------- Google OAuth (one-time refresh-token bootstrap + token minting) ----------
const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/calendar.readonly",
].join(" ");

app.get("/auth/google", requireAuth, (req, res) => {
  if (!GOOGLE_CLIENT_ID || !BASE_URL) return res.status(500).send("Set GOOGLE_CLIENT_ID and BASE_URL first.");
  const url =
    "https://accounts.google.com/o/oauth2/v2/auth?" +
    new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      redirect_uri: `${BASE_URL}/auth/google/callback`,
      response_type: "code",
      scope: GOOGLE_SCOPES,
      access_type: "offline",
      prompt: "consent",
    });
  res.redirect(url);
});

app.get("/auth/google/callback", requireAuth, async (req, res) => {
  try {
    const body = new URLSearchParams({
      code: req.query.code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: `${BASE_URL}/auth/google/callback`,
      grant_type: "authorization_code",
    });
    const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", body });
    const j = await r.json();
    if (!j.refresh_token) return res.status(500).send(`<pre>No refresh_token returned:\n${JSON.stringify(j, null, 2)}</pre>`);
    res.send(`<body style="font-family:sans-serif;max-width:640px;margin:40px auto">
      <h2>Google connected</h2>
      <p>Copy this refresh token into the <code>GOOGLE_REFRESH_TOKEN</code> environment variable on Render, then redeploy. It is shown once — it is not stored anywhere by this app.</p>
      <pre style="background:#eee;padding:12px;border-radius:8px;white-space:break-spaces">${j.refresh_token}</pre></body>`);
  } catch (e) {
    res.status(500).send("OAuth exchange failed: " + e.message);
  }
});

let googleToken = { access_token: null, exp: 0 };
async function googleAccessToken() {
  if (!GOOGLE_REFRESH_TOKEN) throw new Error("GOOGLE_REFRESH_TOKEN not set — visit /auth/google once");
  if (googleToken.access_token && Date.now() < googleToken.exp - 60_000) return googleToken.access_token;
  const body = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    client_secret: GOOGLE_CLIENT_SECRET,
    refresh_token: GOOGLE_REFRESH_TOKEN,
    grant_type: "refresh_token",
  });
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", body });
  const j = await r.json();
  if (!j.access_token) throw new Error("Google token refresh failed: " + JSON.stringify(j));
  googleToken = { access_token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return googleToken.access_token;
}
async function gfetch(url) {
  const token = await googleAccessToken();
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`Google API ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return r.json();
}

// ---------- Stockholm time helpers ----------
const TZ = "Europe/Stockholm";
function stockholmYMD(d = new Date()) {
  return new Intl.DateTimeFormat("sv-SE", { timeZone: TZ }).format(d); // YYYY-MM-DD
}
function addDaysYMD(ymd, n) {
  const d = new Date(ymd + "T12:00:00Z");
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

// ---------- data sources ----------
async function fetchCalendar() {
  const today = stockholmYMD();
  const timeMin = new Date(today + "T00:00:00+02:00").toISOString();
  const timeMax = new Date(addDaysYMD(today, 8) + "T00:00:00+02:00").toISOString();
  const j = await gfetch(
    "https://www.googleapis.com/calendar/v3/calendars/primary/events?" +
      new URLSearchParams({
        timeMin, timeMax, singleEvents: "true", orderBy: "startTime", maxResults: "60", timeZone: TZ,
      })
  );
  return (j.items || [])
    .filter((e) => e.status !== "cancelled")
    .map((e) => ({
      summary: e.summary || "(no title)",
      start: e.start?.dateTime || e.start?.date,
      end: e.end?.dateTime || e.end?.date,
      allDay: !e.start?.dateTime,
      link: e.htmlLink,
      location: e.location || "",
      meet: e.conferenceData ? "video" : "",
      declined: (e.attendees || []).filter((a) => a.responseStatus === "declined" && !a.self).map((a) => a.displayName || a.email),
    }));
}

const NOISE_SUBJECT = /^(tackat (ja|nej)|uppdaterad inbjudan|inbjudan:|avbokat|anteckningar:|notes:|accepted:|declined:|updated invitation)/i;
const NOISE_SENDER = /(gemini-notes@|calendar-notification@|no-?reply.*anthropic|@mail\.anthropic\.com)/i;

async function fetchInbox() {
  const list = await gfetch(
    "https://gmail.googleapis.com/gmail/v1/users/me/threads?" +
      new URLSearchParams({ q: "in:inbox newer_than:2d", maxResults: "25" })
  );
  const threads = list.threads || [];
  let noiseCount = 0;
  const items = [];
  for (const t of threads) {
    const th = await gfetch(
      `https://gmail.googleapis.com/gmail/v1/users/me/threads/${t.id}?` +
        new URLSearchParams({ format: "metadata", metadataHeaders: "Subject" }) +
        "&metadataHeaders=From&metadataHeaders=Date"
    );
    const msgs = th.messages || [];
    if (!msgs.length) continue;
    const first = msgs[0], last = msgs[msgs.length - 1];
    const header = (m, name) => (m.payload?.headers || []).find((h) => h.name.toLowerCase() === name)?.value || "";
    const subject = header(first, "subject") || "(no subject)";
    const from = header(last, "from");
    const fromEmail = (/<([^>]+)>/.exec(from)?.[1] || from).toLowerCase();
    if (NOISE_SUBJECT.test(subject) || NOISE_SENDER.test(fromEmail)) { noiseCount++; continue; }
    const lastIsMine = (last.labelIds || []).includes("SENT") || myEmails.includes(fromEmail);
    const anySent = msgs.some((m) => (m.labelIds || []).includes("SENT"));
    const unread = msgs.some((m) => (m.labelIds || []).includes("UNREAD"));
    const snippet = last.snippet || "";
    let badge = "fyi";
    if (/begär åtkomst|requests access/i.test(snippet)) badge = "action";
    else if (lastIsMine) badge = "you replied";
    else if (anySent) badge = "new reply";
    else if (unread) badge = "unread";
    items.push({
      id: t.id, subject,
      from: from.replace(/<.*>/, "").trim() || fromEmail,
      date: Number(last.internalDate) || null,
      snippet: snippet.slice(0, 180),
      badge,
      link: `https://mail.google.com/mail/u/0/#all/${t.id}`,
    });
  }
  const order = { action: 0, "new reply": 1, unread: 2, fyi: 3, "you replied": 4 };
  items.sort((a, b) => (order[a.badge] ?? 9) - (order[b.badge] ?? 9) || (b.date || 0) - (a.date || 0));
  return { items: items.slice(0, 10), noiseCount };
}

async function asanaGet(path) {
  const r = await fetch(`https://app.asana.com/api/1.0${path}`, {
    headers: { Authorization: `Bearer ${ASANA_TOKEN}` },
  });
  if (!r.ok) throw new Error(`Asana ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return (await r.json()).data;
}

async function fetchAsana() {
  const tasks = await asanaGet(
    `/tasks?assignee=me&workspace=${ASANA_WORKSPACE}&completed_since=now&limit=100&opt_fields=name,due_on,permalink_url`
  );
  const dated = tasks.filter((t) => t.due_on).sort((a, b) => a.due_on.localeCompare(b.due_on));
  const goals = await asanaGet(
    `/tasks?project=${ASANA_GOALS_PROJECT}&opt_fields=name,completed,due_on,permalink_url,memberships.section.name,custom_fields.name,custom_fields.display_value`
  );
  return {
    dated: dated.slice(0, 8).map((t) => ({ name: t.name, due: t.due_on, link: t.permalink_url })),
    undatedCount: tasks.length - dated.length,
    goals: goals.map((g) => ({
      name: g.name,
      link: g.permalink_url,
      section: g.memberships?.[0]?.section?.name || "",
      status: g.custom_fields?.find((f) => f.name === "STATUS")?.display_value || "",
      completion: g.custom_fields?.find((f) => f.name === "COMPLETION")?.display_value || "",
      comment: g.custom_fields?.find((f) => f.name === "COMMENT")?.display_value || "",
    })),
    projectLink: `https://app.asana.com/1/${ASANA_WORKSPACE}/project/${ASANA_GOALS_PROJECT}/list`,
  };
}

// ---- Buddy Analytics via its MCP endpoint (JSON-RPC over streamable HTTP) ----
let mcpSession = null;
async function mcpRpc(method, params, id) {
  const headers = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${BUDDY_API_KEY}`,
  };
  if (mcpSession) headers["Mcp-Session-Id"] = mcpSession;
  const r = await fetch(BUDDY_MCP_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const sid = r.headers.get("mcp-session-id");
  if (sid) mcpSession = sid;
  const text = await r.text();
  if (!r.ok) throw new Error(`Buddy MCP ${r.status}: ${text.slice(0, 300)}`);
  // Response may be plain JSON or an SSE stream; take the last data: line in the SSE case.
  let payload = text.trim();
  if (payload.startsWith("event:") || payload.includes("\ndata:") || payload.startsWith("data:")) {
    const lines = payload.split("\n").filter((l) => l.startsWith("data:"));
    payload = lines[lines.length - 1]?.slice(5).trim() || "{}";
  }
  const j = JSON.parse(payload);
  if (j.error) throw new Error(`Buddy MCP error: ${JSON.stringify(j.error)}`);
  return j.result;
}
let mcpReady = false;
async function mcpEnsure() {
  if (mcpReady) return;
  await mcpRpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "per-dashboard", version: "1.0" },
  }, 1);
  // notification (no id) — fire and forget
  await fetch(BUDDY_MCP_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${BUDDY_API_KEY}`,
      ...(mcpSession ? { "Mcp-Session-Id": mcpSession } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  }).catch(() => {});
  mcpReady = true;
}
async function queryMetric(metrics, grain) {
  await mcpEnsure();
  const result = await mcpRpc("tools/call", {
    name: "query_metric",
    arguments: { metrics, grain, period: { type: "relative", lastN: 2 } },
  }, Date.now());
  const textPart = (result.content || []).find((c) => c.type === "text")?.text;
  const data = result.structuredContent || (textPart ? JSON.parse(textPart) : null);
  if (!data?.rows) throw new Error("Unexpected query_metric response");
  return data;
}
async function fetchKpis() {
  const [dayCounts, dayRev, weekCounts, weekMrr, weekChurn] = await Promise.all([
    queryMetric(["active_users", "new_subscribers", "trial_starts"], "day"),
    queryMetric(["net_revenue_recognized"], "day"),
    queryMetric(["active_paying_users", "net_new_subscribers"], "week"),
    queryMetric(["mrr"], "week"),
    queryMetric(["mrr_churn"], "week"),
  ]);
  const pair = (q, key) => {
    const rows = q.rows;
    if (rows.length < 2) return { curr: rows[0]?.[key] ?? null, prev: null, bucket: rows[0]?.bucket };
    return { prev: rows[rows.length - 2][key], curr: rows[rows.length - 1][key], bucket: rows[rows.length - 1].bucket, prevBucket: rows[rows.length - 2].bucket };
  };
  return {
    daily: {
      dau: pair(dayCounts, "active_users"),
      newSubs: pair(dayCounts, "new_subscribers"),
      trials: pair(dayCounts, "trial_starts"),
      netRevenue: pair(dayRev, "net_revenue_recognized"),
    },
    weekly: {
      wapu: pair(weekCounts, "active_paying_users"),
      netNewSubs: pair(weekCounts, "net_new_subscribers"),
      mrr: pair(weekMrr, "mrr"),
      mrrChurn: pair(weekChurn, "mrr_churn"),
    },
  };
}

// ---------- aggregate + cache ----------
let cache = { at: 0, data: null };
async function collect(fresh) {
  const maxAge = Number(CACHE_SECONDS) * 1000;
  if (!fresh && cache.data && Date.now() - cache.at < maxAge) return cache.data;
  const [calendar, inbox, asana, kpis] = await Promise.allSettled([
    fetchCalendar(), fetchInbox(), fetchAsana(), fetchKpis(),
  ]);
  const val = (s) => (s.status === "fulfilled" ? s.value : null);
  const err = (s) => (s.status === "rejected" ? String(s.reason?.message || s.reason).slice(0, 300) : null);
  const data = {
    pulledAt: new Date().toISOString(),
    calendar: val(calendar), inbox: val(inbox), asana: val(asana), kpis: val(kpis),
    errors: { calendar: err(calendar), inbox: err(inbox), asana: err(asana), kpis: err(kpis) },
  };
  cache = { at: Date.now(), data };
  return data;
}

app.get("/api/data", requireAuth, async (req, res) => {
  try {
    res.json(await collect(req.query.fresh === "1"));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/healthz", (req, res) => res.send("ok"));
app.use("/", requireAuth, express.static("public"));

app.listen(PORT, () => console.log(`Dashboard listening on :${PORT}`));
