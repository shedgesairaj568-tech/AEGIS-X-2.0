# Module 4 Delivery — Frontend

New top-level `frontend` folder. Copy the whole thing into your project
root:

```
AEGIS-X-backend (2)\frontend\   <- new
AEGIS-X-backend (2)\backend\
AEGIS-X-backend (2)\ai_engine\
...etc
```

## Setup

```powershell
cd frontend
npm install
npm run dev
```

Opens at http://localhost:5173. Requires your backend running at
http://localhost:8000 (the default in `.env.local`) — check
`backend\.env`'s `CORS_ORIGINS` includes `http://localhost:5173`.

## What to check first

1. Visit http://localhost:5173 — should redirect to `/login` with a
   dark console-style login page (subtle rotating radar-sweep effect
   in the background)
2. Register a new account, or log in with one you already have
3. Dashboard should load with stat cards, an attack distribution chart,
   and recent alerts (if your database has alerts already — e.g. from
   running Module 9's live_feed_runner)
4. Click "Alerts" in the sidebar, try the status/severity/attack-type
   filters, click any alert row to see its full timeline and report

See `frontend/README.md` for the full design rationale, deployment
instructions, and an honest note on what I could and couldn't verify
visually in my sandbox (no browser screenshot tooling available there —
please look at it yourself and tell me if anything looks off).
