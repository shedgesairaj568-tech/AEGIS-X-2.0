# Module 4 — Frontend (AEGIS-X SOC Console)

React + TypeScript + Tailwind CSS dashboard for AEGIS-X, wired to the
real backend API (Modules 2-3) via a typed service layer that mirrors
the backend's actual Pydantic schemas.

## Scope of this delivery (core-first, as agreed)

- **Login** and **Register** pages
- **Dashboard**: stat cards, attack distribution chart, severity
  breakdown, recent alerts
- **Alerts**: filterable list (status/severity/attack type), pagination,
  and a detail drawer showing the full investigation timeline and
  incident report for any alert (pulling from the `/history` and
  `/reports` endpoints)

Not yet built (next round): a dedicated Threat Timeline page, Settings
page, and CSV export — the underlying backend endpoints for these
already exist from Modules 2-3, so adding the UI is the only remaining
work.

## Design rationale

This is a SOC analyst's working tool, not a marketing site, so the
direction is grounded in that job, not decorative:

- **Dark theme** (`#0B1120` base, not pure black): real SOC tools go
  dark because analysts stare at this for entire shifts in dim
  operations rooms — a genuine ergonomic reason, not just an aesthetic
  default.
- **Amber accent** (`#FFB454`): a deliberate reference to old
  radar/CRT-terminal phosphor — distinctive, and avoids the generic
  teal/acid-green "AI dashboard" look.
- **Severity system** (blue -> amber -> orange -> red) is functional,
  not decorative — it's the same 4-step ramp used server-side in
  `ai_engine/inference/risk_scoring.py`, so the frontend and the AI
  pipeline's own severity logic always agree.
- **IBM Plex Sans + IBM Plex Mono**: Plex is purpose-built for
  enterprise technical software; using a real monospace face for data
  (IPs, timestamps, risk scores) is authentic to the domain.
- **Signature element — the Risk Meter**: `risk_score` renders as a
  segmented signal-strength readout (like a VU meter / radar signal
  indicator) instead of the generic circular gauge every dashboard
  defaults to — it ties to the product's actual job: reading a signal
  out of noisy traffic. See `src/components/RiskMeter.tsx`.
- **Structural device — left-edge severity bars**: every alert row has
  a colored left border indicating severity, reinforced consistently
  rather than relying on a badge alone (`src/components/AlertRow.tsx`).

## Running it locally

```bash
cd frontend
npm install
cp .env.example .env.local   # already present with localhost default
npm run dev
```

Requires the backend running at the URL in `.env.local`
(`VITE_API_BASE_URL`, default `http://localhost:8000`) with
`CORS_ORIGINS` in `backend/.env` including your dev server's origin
(`http://localhost:5173`).

## Deployment

Built for real deployment from the start, not just local dev:

- **API URL is environment-configurable**, not hardcoded — see
  `src/services/apiClient.ts`. Vite resolves `VITE_API_BASE_URL` at
  **build time**, so each deployment target (staging, production) needs
  its own build with the right value baked in — see the Dockerfile's
  `ARG VITE_API_BASE_URL`.
- **`Dockerfile`**: multi-stage build — compiles the app, then serves
  the static output with nginx. `docker/nginx.conf` handles SPA routing
  (any unmatched path falls back to `index.html` so React Router can
  take over client-side).

```bash
docker build --build-arg VITE_API_BASE_URL=https://api.yourdomain.com -t aegis-x-frontend .
docker run -p 8080:80 aegis-x-frontend
```

Add this frontend service to `docker/docker-compose.yml` alongside the
backend once both are deployed together — not included in this delivery
since it depends on your actual production backend URL.

## Verification (and an honest limitation)

**What was actually verified end-to-end in this sandbox:**
- Production build succeeds with zero TypeScript errors
  (`npm run build`)
- Every single source file transforms cleanly through Vite's dev server
  with no syntax/import errors (all 19 files individually checked)
- **Real backend + real frontend dev server run together**: registered
  a real user, logged in, created real alerts via the actual backend
  API, confirmed CORS correctly allows the frontend's origin, and
  confirmed the exact login request the frontend's code makes (same
  headers, same origin, same payload shape) succeeds against the real
  backend and returns a valid token

**What could NOT be verified here**: an actual rendered screenshot. This
sandbox has network access to `registry.npmjs.org` (for installing
packages) but not to the CDN Playwright's browser binaries download
from, so I couldn't take a real screenshot to visually confirm the
design renders as intended — I verified correctness through the build
succeeding, every file compiling without error, and a full real-backend
integration test, but the actual visual result needs your eyes on it.

**Please run `npm run dev` yourself and look at it** — if anything looks
visually off (spacing, colors, a component that doesn't render as
described), tell me and I'll fix it immediately.
