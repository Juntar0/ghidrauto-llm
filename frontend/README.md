# AutoRE Frontend

## Production
For this MVP, the frontend is built into static assets and served by the backend (FastAPI) from `frontend/dist`.

## Dev server (optional)
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Notes:
- If you run the dev server, the backend still runs separately (default `:5555`).
- Most deployments should **not** use the dev server; just run backend + worker.
