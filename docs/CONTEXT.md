# Intune Policy Analyzer — Context for AI Agents

> This file provides context for any AI agent working on this codebase.
> Read AGENTS.md for conventions. Read this file for history, decisions, and gotchas.

## Project Status (as of 2026-04-14)

- **Phase 1** ✅ Auth, policy fetcher (12 types), group resolver, dashboard, group explorer
- **Phase 2** ✅ Conflict analyzer with friendly setting names, scoped analysis
- **Phase 3** 🔲 Optimization engine + export (CSV/HTML/PDF)

**GitHub:** https://github.com/crazytil/intune-policy-analyzer

## Critical Implementation Details

### Python 3.9 Compatibility
System Python is 3.9.6. Backend venv uses Python 3.13 installed via Homebrew at `/opt/homebrew/opt/python@3.13/bin/python3.13`. **All backend files MUST include `from __future__ import annotations`** and use `Optional[X]` / `List[X]` from `typing` for runtime type hints.

### Pydantic CamelCase Serialization (CRITICAL)
Frontend expects camelCase, backend uses snake_case. Bridged via:
- Every Pydantic model: `model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)`
- `_to_camel` function defined in `models.py`
- All FastAPI routes with response models: `response_model_by_alias=True`
- Manual `.model_dump()` calls: `by_alias=True`
**If you add a new model or route, you MUST follow this pattern.**

### Authentication
- MSAL `PublicClientApplication` with interactive browser flow
- Client ID: `14d82eec-204b-4c2f-b7e8-296a70dab67e` (Microsoft Graph PowerShell)
- No new app registration needed
- Delegated read-only scopes
- Token cached in `.token_cache.json` (gitignored)

### Frontend Caching (sessionStorage)
- Policies AND groups cached in `sessionStorage` keyed by tenant+user
- **Policies have `raw` field stripped before caching** — full policy JSON is ~5.3MB which exceeds sessionStorage's 5MB limit. The `stripRawForCache()` function removes the `raw` field
- Groups cached separately under `intune-groups-cache` key
- Both fetched in parallel via `Promise.all` on auth
- Cache cleared on logout or user switch
- "Refresh All" button in dashboard + header forces re-fetch

### Graph API Specifics
- All endpoints use Beta: `https://graph.microsoft.com/beta/`
- `ConsistencyLevel: eventual` header added to ALL requests (in graph_client.py)
- **Groups endpoint requires `$count=true` alongside `$orderby`** — without it, Graph returns 400
- Settings Catalog: `/{id}/settings?$expand=settingDefinitions` for display names
- Conditional Access: NO separate assignments endpoint — extracted from inline `conditions.users.includeGroups/excludeGroups`
- Some endpoints return 403 depending on permissions: powershellScripts, remediationScripts, appConfiguration — handled gracefully with partial results
- Pagination via `@odata.nextLink`

### Conflict Analyzer Architecture
- **Auto-analyzes** on selection — no manual button click
- Three scope modes: All Policies, By Group, By Policy
- By Group includes special entries: "All Users" and "All Devices" (not real groups, but Intune assignment targets)
- Backend endpoints:
  - `GET /api/analyze-conflicts` — tenant-wide
  - `GET /api/analyze-conflicts/group/{group_id}` — group-scoped
  - `GET /api/analyze-conflicts/policy/{policy_id}` — policy-scoped
  - `GET /api/analyze-conflicts/target/{all_users|all_devices}` — special targets
- Setting extraction: ~100 friendly name mappings for device config properties
- Settings Catalog uses `settingDefinitions[].displayName` from `$expand`
- Unmapped names: camelCase → "Title Case" conversion via `_camel_to_title()`
- Values: human-readable display + raw value shown below in monospace
- Frontend `friendlySettingName()` also converts PascalCase/camelCase to readable form

### Frontend Architecture
- React 18 + Vite + TypeScript strict + Tailwind CSS
- Vite proxies `/api/*` to `http://localhost:8099`
- **Data managed centrally in App.tsx** — policies and groups loaded once, passed as props
- GroupExplorer and ConflictAnalyzer receive `groups` prop (do NOT fetch independently)
- Dark/light mode via Tailwind `dark:` classes
- Auth-gated UI: landing page when not signed in
- All overflow handled with `overflow-hidden`, `truncate`, `break-words`

## Running the App

```bash
# Backend (Terminal 1)
cd backend && source venv/bin/activate && uvicorn main:app --reload --port 8099

# Frontend (Terminal 2)
cd frontend && npm run dev
```

Open http://localhost:5173

## Known Issues / Gotchas

1. **sessionStorage limit**: Policies with `raw` field are ~5.3MB. Must strip `raw` before caching
2. **Groups endpoint**: Requires `$count=true` with `$orderby` or Graph returns 400
3. **App Configuration** returns 403 — needs `DeviceManagementApps.Read.All` scope
4. **Conditional Access** returns 400 sometimes — may need `Policy.Read.All` consented
5. **PowerShell/Remediation Scripts** return 403 — need specific permissions
6. Backend uses in-memory `_policies_cache` — restarting clears it (frontend cache persists)
7. The `--reload` flag on uvicorn sometimes hangs during file changes — kill and restart

## File Map

```
backend/
├── main.py              # FastAPI app, 13 routes, in-memory policy cache
├── auth.py              # MSAL PublicClientApplication, token cache
├── graph_client.py      # Async httpx, pagination, 429 retry, semaphore, ConsistencyLevel header
├── policy_fetcher.py    # 12 policy types, parallel fetch, $expand=settingDefinitions
├── group_resolver.py    # Group search, transitive membership, bidirectional
├── conflict_analyzer.py # Setting extraction, ~100 friendly names, overlap detection, 4 analysis modes
├── models.py            # Pydantic models with camelCase aliases (_to_camel)
├── config.py            # Settings from env vars
└── requirements.txt     # Pinned deps

frontend/
├── src/
│   ├── App.tsx           # Auth, data loading, sessionStorage caching, tabs, dark mode
│   ├── components/
│   │   ├── Dashboard.tsx       # Summary cards, cache status, refresh button
│   │   ├── GroupExplorer.tsx    # Bidirectional group↔policy explorer (groups passed as prop)
│   │   └── ConflictAnalyzer.tsx # Auto-analyzing overlap detector with 3 scope modes
│   ├── services/api.ts   # Typed API functions (13 endpoints)
│   └── types/index.ts    # TypeScript interfaces + POLICY_TYPES array
└── vite.config.ts        # Proxy /api → localhost:8099
```

## What's Next (Phase 3)

1. **Optimization Engine** (`backend/optimization_engine.py`):
   - Orphaned policies (assigned to empty/deleted groups)
   - Unused policies (no assignments at all)
   - Overly broad (All Users/All Devices with few actual targets needing it)
   - Consolidation candidates (same group, no conflicts — could merge)
   - Redundant assignments (same policy via parent + child group)

2. **Export Service** (`backend/export_service.py`):
   - CSV, HTML, PDF for each view
   - Filterable before export

3. **Frontend**: Enable Optimization tab, add export buttons to all views
