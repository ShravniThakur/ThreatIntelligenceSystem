# Bank of India — APK Threat Intelligence Console

Professional, BOI-branded frontend for the APK threat-analysis backend.
Built with **Vite + React + Tailwind**, with **framer-motion** animations,
**recharts** dashboard charts, **d3** network graph, and **react-markdown** reports.

## Develop

```bash
cd frontend
npm install            # if the npm cache is root-owned: npm install --cache /tmp/npmcache
npm run dev            # Vite dev server on http://localhost:5173
```

The backend must be running on `http://localhost:8001`
(`cd backend && uvicorn main:app --port 8001 --workers 1`). CORS is open there,
so the dev server talks to it directly.

## Production build

```bash
npm run build          # emits frontend/dist
```

`backend/main.py` automatically serves `frontend/dist` at `http://localhost:8001/`
when it exists (same-origin). For a same-origin build, set the API base to relative:

```bash
VITE_API_BASE= npm run build
```

> Note: deep-link refreshes (e.g. reloading `/result/<hash>` directly) work under
> the Vite dev server. Under the backend's static mount they rely on client-side
> navigation; a SPA catch-all route in the backend would make hard refreshes work
> too (optional follow-up).

## Structure

- `src/components/layout` — Sidebar, Topbar, AppShell (BOI shell)
- `src/components/ui` — Card, Gauge, Pill, StatCard, CountUp, SectionTitle
- `src/pages` — Dashboard, Analyze, Result, History
- `src/panels` — the analysis panels (ported 1:1 from the old single-file UI)
- `src/lib` — `api.js` (fetch + SSE), `theme.js` (severity colors)

The previous single-file UI is preserved as `index.legacy.html`.
