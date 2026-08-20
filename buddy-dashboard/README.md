# Per — Daily Dashboard (hosted)

A single small Node/Express service that serves your dashboard behind a password and
fetches **live** on every page load and every ↻ Refresh click, from four sources:
Google Calendar, Gmail, Asana, and Buddy Analytics (via its MCP API).

No database. Nothing is stored server-side except a short in-memory cache
(default 120 s; the Refresh button bypasses it).

## Security model — read this first

This page renders your email and calendar. It is protected by one shared password
(signed session cookie, 30 days). That is adequate for a personal tool if the
password is long and the URL is not shared. Do not put this on a public/guessable
URL without the password set. All secrets live in Render environment variables —
never in the repo.

## 1. Push to a private GitHub repo

```bash
cd buddy-dashboard
git init && git add -A && git commit -m "Dashboard"
# create a PRIVATE repo on github.com, then:
git remote add origin git@github.com:<you>/per-dashboard.git
git push -u origin main
```

## 2. Create the Google OAuth client (one time, ~10 min)

1. Go to https://console.cloud.google.com → create a project (e.g. "per-dashboard").
2. **APIs & Services → Library**: enable **Gmail API** and **Google Calendar API**.
3. **APIs & Services → OAuth consent screen**: External, app name "Per Dashboard",
   add your own email as a **test user**. (Stays in "Testing" mode — fine for
   personal use. Note: Google expires refresh tokens for Testing-mode apps after
   7 days **unless** the app's publishing status is set to In production, so after
   testing works, click "Publish app". No verification is needed for these scopes
   at personal scale.)
4. **Credentials → Create credentials → OAuth client ID → Web application**.
   Authorized redirect URI: `https://<your-app>.onrender.com/auth/google/callback`
   (add `http://localhost:8080/auth/google/callback` too if you want to run locally).
5. Save the **Client ID** and **Client secret**.

## 3. Deploy on Render

1. render.com → **New → Web Service** → connect the private repo.
2. Runtime Node, build `npm install`, start `npm start`. Free tier works
   (it sleeps after idle; first load takes ~30 s to wake — Starter keeps it always-on).
3. Set environment variables (see `.env.example` for the full list):
   `BASE_URL`, `DASHBOARD_PASSWORD`, `SESSION_SECRET`, `GOOGLE_CLIENT_ID`,
   `GOOGLE_CLIENT_SECRET`, `ASANA_TOKEN`, `BUDDY_API_KEY`
   (leave `GOOGLE_REFRESH_TOKEN` unset for now).
4. Deploy.

## 4. Connect Google (one time)

1. Open `https://<your-app>.onrender.com`, sign in with your dashboard password.
2. Visit `https://<your-app>.onrender.com/auth/google` → approve with the Google
   account that owns the calendar/inbox (per@matters.inc, judging by the calendar).
3. The callback page shows a **refresh token once** — copy it into the
   `GOOGLE_REFRESH_TOKEN` env var on Render and redeploy.

Done. The dashboard is live at your Render URL from any device.

## Tokens you need and where to get them

| Env var | Where |
|---|---|
| `ASANA_TOKEN` | Asana → Settings → Apps → Developer apps → Personal access token |
| `BUDDY_API_KEY` | analytics-web-prod.onrender.com → /keys |
| `GOOGLE_*` | step 2–4 above |

## Notes & limitations

- **Inbox triage is rule-based** (RSVP noise filtered by subject; "action" /
  "new reply" / "you replied" badges from thread state). It is not the
  Claude-curated triage from the Cowork artifact — a server can't replicate that
  judgment. If a rule misfires, adjust `NOISE_SUBJECT` / `NOISE_SENDER` in `server.js`.
- **Buddy Analytics** is called through its MCP endpoint (JSON-RPC). If the
  analytics team ships a plain REST API, `fetchKpis()` is the only function to swap.
- If one source fails, the other three still render; the failing panel shows the error.
- Auto-refreshes data every 15 min while a tab is open.
- To change which KPIs are shown, edit the five `queryMetric(...)` calls in
  `fetchKpis()` (metric slugs from the Buddy Analytics catalog; one query per
  format kind — counts, currency and percent can't be mixed in one call).

## Run locally (optional)

```bash
cp .env.example .env   # fill it in
node --env-file=.env server.js
# http://localhost:8080  (set BASE_URL=http://localhost:8080 for the OAuth flow)
```
