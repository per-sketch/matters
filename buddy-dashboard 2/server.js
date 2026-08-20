// Per's Dashboard — server v2
// Live-fetches Google Calendar, Gmail, Asana and Buddy Analytics on demand.
// v2: KPI trend series, funnel metrics, Claude-powered inbox triage (optional),
// dismissable mails (Redis), reply-from-dashboard (requires gmail.send scope),
// this-week/next-week calendar with join links, Asana Today/This week sections.

import express from "express";
import crypto from "node:crypto";
import { createClient } from "redis";

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ---------- config ----------
const {
  PORT = 8080,
  BASE_URL,
  DASHBOARD_PASSWORD,
  SESSION_SECRET,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REFRESH_TOKEN,
  ASANA_TOKEN,
  ASANA_WORKSPACE = "1208551054165653",
  ASANA_GOALS_PROJECT = "1217560633887654",
  BUDDY_MCP_URL = "https://analytics-web-prod.onrender.com/api/mcp",
  BUDDY_API_KEY,
  ANTHROPIC_API_KEY, // optional — enables Claude inbox triage
  ANTHROPIC_MODEL = "claude-haiku-4-5",
  REDIS_URL, // optional — persists dismissed mails
  MY_EMAILS = "per@matters.inc,per@joinbuddy.co",
  CACHE_SECONDS = "120",
} = process.env;

if (!DASHBOARD_PASSWORD || !SESSION_SECRET) {
  console.error("FATAL: DASHBOARD_PASSWORD and SESSION_SECRET must be set.");
  process.exit(1);
}
const myEmails = MY_EMAILS.split(",").map((s) => s.trim().toLowerCase());

// ---------- redis (optional; in-memory fallback) ----------
let redis = null;
const memDismissed = new Set();
if (REDIS_URL) {
  redis = createClient({ url: REDIS_URL });
  redis.on("error", (e) => console.error("redis:", e.message));
  redis.connect().catch((e) => { console.error("redis connect failed:", e.message); redis = null; });
}
async function getDismissed() {
  if (redis?.isOpen) try { return new Set(await redis.sMembers("dismissed")); } catch {}
  return memDismissed;
}
async function addDismissed(id) {
  memDismissed.add(id);
  if (redis?.isOpen) try { await redis.sAdd("dismissed", id); } catch {}
}
async function clearDismissed() {
  memDismissed.clear();
  if (redis?.isOpen) try { await redis.del("dismissed"); } catch {}
}

// ---------- session ----------
function sign(v) { return crypto.createHmac("sha256", SESSION_SECRET).update(v).digest("base64url"); }
function makeSession() { const p = `ok.${Date.now() + 30 * 24 * 3600 * 1000}`; return `${p}.${sign(p)}`; }
function checkSession(cookieHeader) {
  const m = /(?:^|;\s*)dash_session=([^;]+)/.exec(cookieHeader || "");
  if (!m) return false;
  const parts = decodeURIComponent(m[1]).split(".");
  if (parts.length !== 3) return false;
  const payload = `${parts[0]}.${parts[1]}`;
  return sign(payload) === parts[2] && parts[0] === "ok" && Number(parts[1]) > Date.now();
}
function requireAuth(req, res, next) {
  if (checkSession(req.headers.cookie)) return next();
  if (req.path.startsWith("/api/")) return res.status(401).json({ error: "unauthorized" });
  res.redirect("/login");
}
function passwordOk(pw) {
  const a = Buffer.from(String(pw || "")), b = Buffer.from(DASHBOARD_PASSWORD);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

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
    res.setHeader("Set-Cookie",
      `dash_session=${encodeURIComponent(makeSession())}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 3600}`);
    return res.redirect("/");
  }
  res.status(401).send(loginPage("Wrong password."));
});

// ---------- Google OAuth ----------
// NOTE: gmail.send is required for reply-from-dashboard. If you connected Google
// before v2, visit /auth/google again and replace GOOGLE_REFRESH_TOKEN.
const GOOGLE_SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/calendar.readonly",
].join(" ");

app.get("/auth/google", requireAuth, (req, res) => {
  if (!GOOGLE_CLIENT_ID || !BASE_URL) return res.status(500).send("Set GOOGLE_CLIENT_ID and BASE_URL first.");
  res.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/google/callback`,
    response_type: "code", scope: GOOGLE_SCOPES, access_type: "offline", prompt: "consent",
  }));
});
app.get("/auth/google/callback", requireAuth, async (req, res) => {
  try {
    const r = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      body: new URLSearchParams({
        code: req.query.code, client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: `${BASE_URL}/auth/google/callback`, grant_type: "authorization_code",
      }),
    });
    const j = await r.json();
    if (!j.refresh_token) return res.status(500).send(`<pre>No refresh_token:\n${JSON.stringify(j, null, 2)}</pre>`);
    res.send(`<body style="font-family:sans-serif;max-width:640px;margin:40px auto"><h2>Google connected</h2>
      <p>Copy this refresh token into <code>GOOGLE_REFRESH_TOKEN</code> on Render (replace the old one), then redeploy. Shown once, stored nowhere.</p>
      <pre style="background:#eee;padding:12px;border-radius:8px;white-space:break-spaces">${j.refresh_token}</pre></body>`);
  } catch (e) { res.status(500).send("OAuth exchange failed: " + e.message); }
});

let googleToken = { access_token: null, exp: 0 };
async function googleAccessToken() {
  if (!GOOGLE_REFRESH_TOKEN) throw new Error("GOOGLE_REFRESH_TOKEN not set — visit /auth/google once");
  if (googleToken.access_token && Date.now() < googleToken.exp - 60_000) return googleToken.access_token;
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID, client_secret: GOOGLE_CLIENT_SECRET,
      refresh_token: GOOGLE_REFRESH_TOKEN, grant_type: "refresh_token",
    }),
  });
  const j = await r.json();
  if (!j.access_token) throw new Error("Google token refresh failed: " + JSON.stringify(j));
  googleToken = { access_token: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return googleToken.access_token;
}
async function gfetch(url, init = {}) {
  const token = await googleAccessToken();
  const r = await fetch(url, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers || {}) } });
  if (!r.ok) throw new Error(`Google API ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return r.json();
}

// ---------- time helpers ----------
const TZ = "Europe/Stockholm";
const ymdOf = (d) => new Intl.DateTimeFormat("sv-SE", { timeZone: TZ }).format(d);
function addDaysYMD(ymd, n) { const d = new Date(ymd + "T12:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }
function stockholmWeekday(ymd) { // 0=Mon..6=Sun
  const names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
  const wd = new Intl.DateTimeFormat("en-GB", { timeZone: TZ, weekday: "short" }).format(new Date(ymd + "T12:00:00Z"));
  return names.indexOf(wd);
}

// ---------- calendar ----------
async function fetchCalendar() {
  const today = ymdOf(new Date());
  const daysLeftOfWeek = 6 - stockholmWeekday(today); // through Sunday
  const endOfNextWeek = addDaysYMD(today, daysLeftOfWeek + 8); // exclusive bound
  const j = await gfetch("https://www.googleapis.com/calendar/v3/calendars/primary/events?" + new URLSearchParams({
    timeMin: new Date(today + "T00:00:00+02:00").toISOString(),
    timeMax: new Date(endOfNextWeek + "T00:00:00+02:00").toISOString(),
    singleEvents: "true", orderBy: "startTime", maxResults: "80", timeZone: TZ,
  }));
  const endOfThisWeek = addDaysYMD(today, daysLeftOfWeek); // last day of this week
  return (j.items || []).filter((e) => e.status !== "cancelled").map((e) => {
    const start = e.start?.dateTime || e.start?.date;
    const teams = /https:\/\/teams\.microsoft\.com\/[^\s<">]+/.exec(e.description || "")?.[0];
    return {
      summary: e.summary || "(no title)",
      start, end: e.end?.dateTime || e.end?.date,
      allDay: !e.start?.dateTime,
      link: e.htmlLink,
      joinUrl: e.hangoutLink || e.conferenceData?.entryPoints?.find((p) => p.entryPointType === "video")?.uri || teams || null,
      declined: (e.attendees || []).filter((a) => a.responseStatus === "declined" && !a.self).map((a) => a.displayName || a.email),
      week: ymdOf(new Date(start)) <= endOfThisWeek ? "this" : "next",
    };
  });
}

// ---------- inbox ----------
const NOISE_SUBJECT = /^(tackat (ja|nej)|uppdaterad inbjudan|inbjudan:|avbokat|anteckningar:|notes:|accepted:|declined:|updated invitation)/i;
const NOISE_SENDER = /(gemini-notes@|calendar-notification@|no-?reply.*anthropic|@mail\.anthropic\.com)/i;

async function fetchInbox() {
  const list = await gfetch("https://gmail.googleapis.com/gmail/v1/users/me/threads?" +
    new URLSearchParams({ q: "in:inbox newer_than:2d", maxResults: "25" }));
  const dismissed = await getDismissed();
  let noiseCount = 0, dismissedCount = 0;
  const items = [];
  for (const t of list.threads || []) {
    if (dismissed.has(t.id)) { dismissedCount++; continue; }
    const th = await gfetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads/${t.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date`);
    const msgs = th.messages || [];
    if (!msgs.length) continue;
    const header = (m, name) => (m.payload?.headers || []).find((h) => h.name.toLowerCase() === name)?.value || "";
    const first = msgs[0], last = msgs[msgs.length - 1];
    const subject = header(first, "subject") || "(no subject)";
    const from = header(last, "from");
    const fromEmail = (/<([^>]+)>/.exec(from)?.[1] || from).toLowerCase();
    if (NOISE_SUBJECT.test(subject) || NOISE_SENDER.test(fromEmail)) { noiseCount++; continue; }
    const lastIsMine = (last.labelIds || []).includes("SENT") || myEmails.includes(fromEmail);
    const anySent = msgs.some((m) => (m.labelIds || []).includes("SENT"));
    const unread = msgs.some((m) => (m.labelIds || []).includes("UNREAD"));
    items.push({
      id: t.id, subject,
      from: from.replace(/<.*>/, "").trim() || fromEmail,
      date: Number(last.internalDate) || null,
      snippet: (last.snippet || "").slice(0, 200),
      lastIsMine, anySent, unread,
      link: `https://mail.google.com/mail/u/0/#all/${t.id}`,
    });
  }
  const triaged = await triage(items);
  const order = { "needs reply": 0, action: 1, "new reply": 2, unread: 3, fyi: 4, "awaiting reply": 5, answered: 6 };
  triaged.sort((a, b) => (order[a.badge] ?? 9) - (order[b.badge] ?? 9) || (b.date || 0) - (a.date || 0));
  return { items: triaged.slice(0, 12), noiseCount, dismissedCount, triageMode: ANTHROPIC_API_KEY ? "claude" : "rules" };
}

function ruleBadge(m) {
  if (/begär åtkomst|requests access/i.test(m.snippet)) return "action";
  if (m.lastIsMine) return "awaiting reply";
  if (m.anySent) return "new reply";
  if (m.unread) return "unread";
  return "fyi";
}

async function triage(items) {
  if (!ANTHROPIC_API_KEY || !items.length) return items.map((m) => ({ ...m, badge: ruleBadge(m), summary: null }));
  try {
    const input = items.map((m) => ({
      id: m.id, subject: m.subject, from: m.from, snippet: m.snippet,
      i_sent_the_last_message: m.lastIsMine, i_replied_earlier_in_thread: m.anySent, unread: m.unread,
    }));
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
      body: JSON.stringify({
        model: ANTHROPIC_MODEL, max_tokens: 1500,
        messages: [{ role: "user", content:
          `Triage these email threads for Per (CEO). For each, pick ONE badge:
"needs reply" (someone asked Per something he hasn't answered), "action" (something to do, e.g. access request, send an invite, pay), "awaiting reply" (Per replied, waiting on others), "new reply" (new message in a thread Per is active in), "fyi".
Also write a one-line summary (max 15 words, same language as the email).
Reply with ONLY a JSON array: [{"id":"...","badge":"...","summary":"..."}]. No other text.
Threads: ${JSON.stringify(input)}` }],
      }),
    });
    if (!r.ok) throw new Error(`anthropic ${r.status}`);
    const j = await r.json();
    const text = (j.content || []).map((c) => c.text || "").join("");
    const arr = JSON.parse(text.slice(text.indexOf("["), text.lastIndexOf("]") + 1));
    const byId = Object.fromEntries(arr.map((x) => [x.id, x]));
    return items.map((m) => ({ ...m, badge: byId[m.id]?.badge || ruleBadge(m), summary: byId[m.id]?.summary || null }));
  } catch (e) {
    console.error("claude triage failed, falling back to rules:", e.message);
    return items.map((m) => ({ ...m, badge: ruleBadge(m), summary: null }));
  }
}

// ---------- reply from dashboard ----------
function encodeMimeWord(s) { return /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${Buffer.from(s, "utf8").toString("base64")}?=`; }

app.post("/api/reply", requireAuth, async (req, res) => {
  try {
    const { threadId, body } = req.body || {};
    if (!threadId || !body?.trim()) return res.status(400).json({ error: "threadId and body required" });
    const th = await gfetch(`https://gmail.googleapis.com/gmail/v1/users/me/threads/${threadId}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Reply-To&metadataHeaders=Message-ID`);
    const msgs = th.messages || [];
    const header = (m, name) => (m.payload?.headers || []).find((h) => h.name.toLowerCase() === name.toLowerCase())?.value || "";
    // last message not sent by me → recipient
    const lastOther = [...msgs].reverse().find((m) => {
      const f = (/<([^>]+)>/.exec(header(m, "From"))?.[1] || header(m, "From")).toLowerCase();
      return !(m.labelIds || []).includes("SENT") && !myEmails.includes(f);
    }) || msgs[msgs.length - 1];
    const to = header(lastOther, "Reply-To") || header(lastOther, "From");
    const msgId = header(msgs[msgs.length - 1], "Message-ID");
    let subject = header(msgs[0], "Subject") || "";
    if (!/^re:/i.test(subject)) subject = "Re: " + subject;
    const raw = [
      `To: ${to}`,
      `Subject: ${encodeMimeWord(subject)}`,
      msgId ? `In-Reply-To: ${msgId}` : null,
      msgId ? `References: ${msgId}` : null,
      `Content-Type: text/plain; charset=UTF-8`,
      `Content-Transfer-Encoding: base64`,
      ``, Buffer.from(body, "utf8").toString("base64"),
    ].filter((l) => l !== null).join("\r\n");
    const sent = await gfetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw: Buffer.from(raw).toString("base64url"), threadId }),
    });
    cache = { at: 0, data: null };
    res.json({ ok: true, id: sent.id, to });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/api/dismiss", requireAuth, async (req, res) => {
  const { threadId } = req.body || {};
  if (!threadId) return res.status(400).json({ error: "threadId required" });
  await addDismissed(threadId);
  cache = { at: 0, data: null };
  res.json({ ok: true });
});
app.post("/api/dismiss/clear", requireAuth, async (req, res) => {
  await clearDismissed(); cache = { at: 0, data: null }; res.json({ ok: true });
});

// ---------- asana ----------
async function asanaGet(path) {
  const r = await fetch(`https://app.asana.com/api/1.0${path}`, { headers: { Authorization: `Bearer ${ASANA_TOKEN}` } });
  if (!r.ok) throw new Error(`Asana ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return (await r.json()).data;
}
async function fetchAsana() {
  const tasks = await asanaGet(`/tasks?assignee=me&workspace=${ASANA_WORKSPACE}&completed_since=now&limit=100&opt_fields=name,due_on,permalink_url,assignee_section.name`);
  const secName = (t) => (t.assignee_section?.name || "").toLowerCase();
  const todaySec = tasks.filter((t) => /today|idag/.test(secName(t)));
  const weekSec = tasks.filter((t) => /week|vecka/.test(secName(t)));
  const dated = tasks.filter((t) => t.due_on).sort((a, b) => a.due_on.localeCompare(b.due_on));
  const goals = await asanaGet(`/tasks?project=${ASANA_GOALS_PROJECT}&opt_fields=name,completed,due_on,permalink_url,assignee.name,memberships.section.name,custom_fields.name,custom_fields.display_value`);
  const cf = (g, n) => g.custom_fields?.find((f) => f.name === n)?.display_value || "";
  return {
    today: todaySec.map((t) => ({ name: t.name, due: t.due_on, link: t.permalink_url })),
    thisWeek: weekSec.map((t) => ({ name: t.name, due: t.due_on, link: t.permalink_url })),
    dated: dated.slice(0, 8).map((t) => ({ name: t.name, due: t.due_on, link: t.permalink_url })),
    openCount: tasks.length,
    goals: goals.filter((g) => !g.completed).map((g) => ({
      name: g.name, link: g.permalink_url, owner: g.assignee?.name || "",
      section: g.memberships?.[0]?.section?.name || "—",
      status: cf(g, "STATUS"), completion: cf(g, "COMPLETION"), comment: cf(g, "COMMENT"), due: g.due_on,
    })),
    projectLink: `https://app.asana.com/1/${ASANA_WORKSPACE}/project/${ASANA_GOALS_PROJECT}/list`,
  };
}

// ---------- Buddy Analytics (MCP JSON-RPC) ----------
let mcpSession = null, mcpReady = false;
async function mcpRpc(method, params, id) {
  const headers = {
    "Content-Type": "application/json", Accept: "application/json, text/event-stream",
    Authorization: `Bearer ${BUDDY_API_KEY}`, ...(mcpSession ? { "Mcp-Session-Id": mcpSession } : {}),
  };
  const r = await fetch(BUDDY_MCP_URL, { method: "POST", headers, body: JSON.stringify({ jsonrpc: "2.0", id, method, params }) });
  const sid = r.headers.get("mcp-session-id"); if (sid) mcpSession = sid;
  const text = await r.text();
  if (!r.ok) { mcpReady = false; throw new Error(`Buddy MCP ${r.status}: ${text.slice(0, 200)}`); }
  let payload = text.trim();
  if (payload.startsWith("event:") || payload.startsWith("data:") || payload.includes("\ndata:")) {
    const lines = payload.split("\n").filter((l) => l.startsWith("data:"));
    payload = lines[lines.length - 1]?.slice(5).trim() || "{}";
  }
  const j = JSON.parse(payload);
  if (j.error) throw new Error(`Buddy MCP error: ${JSON.stringify(j.error)}`);
  return j.result;
}
async function mcpEnsure() {
  if (mcpReady) return;
  await mcpRpc("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "per-dashboard", version: "2.0" } }, 1);
  await fetch(BUDDY_MCP_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${BUDDY_API_KEY}`, ...(mcpSession ? { "Mcp-Session-Id": mcpSession } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
  }).catch(() => {});
  mcpReady = true;
}
async function queryMetric(metrics, grain, lastN) {
  await mcpEnsure();
  const result = await mcpRpc("tools/call", { name: "query_metric", arguments: { metrics, grain, period: { type: "relative", lastN } } }, Date.now());
  const textPart = (result.content || []).find((c) => c.type === "text")?.text;
  const data = result.structuredContent || (textPart ? JSON.parse(textPart) : null);
  if (!data?.rows) throw new Error("Unexpected query_metric response");
  return data;
}
async function fetchKpis() {
  const [dayCounts, dayRev, weekCounts, weekMrr, weekChurn, weekFunnel, weekTrialConv] = await Promise.all([
    queryMetric(["active_users", "new_subscribers", "trial_starts"], "day", 14),
    queryMetric(["net_revenue_recognized"], "day", 14),
    queryMetric(["active_paying_users", "net_new_subscribers"], "week", 12),
    queryMetric(["mrr"], "week", 12),
    queryMetric(["mrr_churn"], "week", 12),
    queryMetric(["installs"], "week", 12),
    queryMetric(["pct_trial_to_paying"], "week", 12),
  ]);
  const series = (q, key) => ({
    values: q.rows.map((r) => r[key] ?? null),
    buckets: q.rows.map((r) => r.bucket),
  });
  return {
    daily: {
      dau: series(dayCounts, "active_users"),
      newSubs: series(dayCounts, "new_subscribers"),
      trials: series(dayCounts, "trial_starts"),
      netRevenue: series(dayRev, "net_revenue_recognized"),
    },
    weekly: {
      wapu: series(weekCounts, "active_paying_users"),
      netNewSubs: series(weekCounts, "net_new_subscribers"),
      mrr: series(weekMrr, "mrr"),
      mrrChurn: series(weekChurn, "mrr_churn"),
      installs: series(weekFunnel, "installs"),
      trialToPaying: series(weekTrialConv, "pct_trial_to_paying"),
    },
  };
}

// ---------- aggregate + cache ----------
let cache = { at: 0, data: null };
async function collect(fresh) {
  const maxAge = Number(CACHE_SECONDS) * 1000;
  if (!fresh && cache.data && Date.now() - cache.at < maxAge) return cache.data;
  const [calendar, inbox, asana, kpis] = await Promise.allSettled([fetchCalendar(), fetchInbox(), fetchAsana(), fetchKpis()]);
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
  try { res.json(await collect(req.query.fresh === "1")); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get("/healthz", (req, res) => res.send("ok"));
app.use("/", requireAuth, express.static("public"));

app.listen(PORT, () => console.log(`Dashboard v2 listening on :${PORT}`));
