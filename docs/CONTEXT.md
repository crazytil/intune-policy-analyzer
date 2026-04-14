# Intune Policy Analyzer — Context for AI Agents

> This file provides context for any AI agent working on this codebase.
> Read AGENTS.md for conventions. Read this file for history, decisions, and gotchas.

## Project Status (as of 2026-04-14)

- **Phase 1** ✅ Auth, policy fetcher (12 types), group resolver, dashboard, group explorer
- **Phase 2** ✅ Conflict analyzer with friendly setting names
- **Phase 3** 🔲 Optimization engine + export (CSV/HTML/PDF)

## Critical Implementation Details

### Python 3.9 Compatibility
The system Python is 3.9.6. A Python 3.13 venv was installed via Homebrew at `/opt/homebrew/opt/python@3.13/bin/python3.13` and used for `backend/venv/`. However, **all backend files MUST include `from __future__ import annotations`** at the top and use `Optional[X]` / `List[X]` from `typing` for runtime type hints (not `X | None` or `list[X]` syntax).

### Pydantic CamelCase Serialization
The frontend expects camelCase JSON keys (`isAuthenticated`, `displayName`, `policyType`). The backend uses snake_case Python attributes (`is_authenticated`, `display_name`, `policy_type`). This is bridged via:
- Every Pydantic model has `model_config = ConfigDict(alias_generator=_to_camel, populate_by_name=True)`
- The `_to_camel` function is defined in `models.py`
- All FastAPI routes with response models use `response_model_by_alias=True`
- Manual `.model_dump()` calls use `by_alias=True`

**If you add a new model or route, you MUST follow this pattern or the frontend will break silently.**

### Authentication
- Uses MSAL `PublicClientApplication` with interactive browser flow
- Client ID: `14d82eec-204b-4c2f-b7e8-296a70dab67e` (Microsoft Graph PowerShell / "Microsoft Graph Command Line Tools")
- No new app registration needed — reuses the enterprise app already in the tenant
- Delegated permissions only, read-only scopes
- Token cached in `.token_cache.json` (gitignored)
- The user's tenant: `tburg.onmicrosoft.com`, user: `ga2@tburg.onmicrosoft.com`

### Graph API Specifics
- All endpoints use Beta: `https://graph.microsoft.com/beta/`
- `ConsistencyLevel: eventual` header is required for group search with `$count`/`$search`
- Settings Catalog settings fetch uses `$expand=settingDefinitions` to get display names
- Conditional Access has NO separate assignments endpoint — assignments are extracted from inline `conditions.users.includeGroups/excludeGroups`
- Some policy types return 403 (powershellScripts, remediationScripts, appConfiguration) depending on user permissions — this is handled gracefully with partial results
- Pagination handled via `@odata.nextLink`

### Frontend Architecture
- React 18 + Vite + TypeScript strict + Tailwind CSS
- Vite proxies `/api/*` to `http://localhost:8099`
- Policies auto-load on authentication (useEffect in App.tsx)
- Groups load all on mount in GroupExplorer (GET /api/groups), filtered client-side
- Dark/light mode via Tailwind `dark:` classes + class strategy on `<html>`
- Auth-gated UI: landing page when not signed in, tabs + content when signed in

### Conflict Analyzer
- Extracts settings from all policy types into normalized format
- ~100 friendly name mappings for device config/compliance properties
- Settings Catalog uses `settingDefinitions[].displayName` from `$expand`
- Unmapped setting names fall back to camelCase → "Title Case" conversion
- Values displayed as human-readable: "Enabled"/"Disabled"/"Required" etc.
- Groups by setting key, shows only settings in 2+ policies (overlapping)

## Known Issues / Gotchas

1. **App Configuration** endpoint returns 403 — requires `DeviceManagementApps.Read.All` scope which isn't in the default set
2. **Conditional Access** returns 400 sometimes — may need `Policy.Read.All` scope consented
3. **PowerShell/Remediation Scripts** return 403 — need specific permissions
4. The Graph PowerShell enterprise app accumulates consented scopes over time. If a scope hasn't been consented, MSAL will prompt at login
5. The backend uses in-memory cache for policies — restarting the backend clears the cache

## File Map

```
backend/
├── main.py              # FastAPI app, 11 routes, in-memory policy cache
├── auth.py              # MSAL PublicClientApplication, token cache
├── graph_client.py      # Async httpx, pagination, 429 retry, semaphore
├── policy_fetcher.py    # 12 policy types, parallel fetch, settings detail
├── group_resolver.py    # Group search, transitive membership, bidirectional
├── conflict_analyzer.py # Setting extraction, friendly names, overlap detection
├── models.py            # Pydantic models with camelCase aliases
├── config.py            # Settings from env vars
└── requirements.txt     # Pinned deps

frontend/
├── src/
│   ├── App.tsx           # Auth, tabs, dark mode, auto-load policies
│   ├── components/
│   │   ├── Dashboard.tsx       # Summary cards, policy-by-type breakdown
│   │   ├── GroupExplorer.tsx    # Bidirectional group↔policy explorer
│   │   └── ConflictAnalyzer.tsx # Overlapping settings analysis
│   ├── services/api.ts   # Typed API functions
│   └── types/index.ts    # TypeScript interfaces
└── vite.config.ts        # Proxy /api → localhost:8099
```

## What's Next (Phase 3)

1. **Optimization Engine** (`backend/optimization_engine.py`):
   - Orphaned policies (assigned to empty/deleted groups)
   - Unused policies (no assignments)
   - Overly broad (All Users/All Devices with few actual targets)
   - Consolidation candidates (same group, no conflicts)
   - Redundant assignments (parent + child group)

2. **Export Service** (`backend/export_service.py`):
   - CSV, HTML, PDF for each view
   - Filterable before export

3. **Frontend**: Enable Optimization tab, add export buttons
