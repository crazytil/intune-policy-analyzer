# Intune Policy Analyzer — Agent Instructions

## Project Overview

A locally-run web application for analyzing Microsoft Intune policies with a focus on group-centric analysis and policy optimization. React frontend + Python FastAPI backend, using Microsoft Graph API with delegated auth via the existing Graph PowerShell enterprise app.

## Tech Stack

- **Frontend:** React 18+ with Vite, TypeScript, Tailwind CSS
- **Backend:** Python 3.11+, FastAPI, MSAL Python, httpx (async)
- **Auth:** MSAL Python with Graph PowerShell client ID `14d82eec-204b-4c2f-b7e8-296a70dab67e`
- **API:** Microsoft Graph API Beta

## Architecture

- Frontend runs on `localhost:5173`, backend on `localhost:8099`
- Frontend proxies `/api/*` to backend via Vite config
- Backend handles all Graph API calls with async httpx
- Token cached in `.token_cache.json` (gitignored)

## Key Conventions

### Backend (Python)
- Use `async def` for all route handlers and Graph API calls
- Use Pydantic models for all request/response schemas in `models.py`
- Use semaphore-controlled concurrency for parallel Graph API calls (max 4 concurrent)
- All Graph API endpoints use the Beta version: `https://graph.microsoft.com/beta/`
- Handle pagination via `@odata.nextLink`
- Log errors but don't crash — partial results are acceptable (some policy types may fail)

### Frontend (TypeScript/React)
- Functional components with hooks only
- TypeScript strict mode
- Tailwind CSS for all styling — no CSS files
- API calls go through `services/api.ts`
- Types defined in `types/index.ts`

### Authentication
- NEVER create a new app registration — always use Graph PowerShell client ID
- NEVER request write scopes — this tool is read-only
- Token cache file must NEVER be committed to git

### Security
- Never log or display access tokens in the UI
- Never store tenant data on disk beyond the session
- `.token_cache.json` is gitignored

## File Organization

- `backend/main.py` — FastAPI app setup, CORS, route definitions
- `backend/auth.py` — MSAL auth flow, token acquisition and refresh
- `backend/graph_client.py` — Reusable async Graph API client with auth header injection
- `backend/policy_fetcher.py` — Policy type definitions, fetching all types with assignments/settings
- `backend/group_resolver.py` — Group search, nested membership resolution
- `backend/conflict_analyzer.py` — Setting normalization, conflict/duplicate detection
- `backend/optimization_engine.py` — Orphaned, unused, broad, consolidation, redundant detection
- `backend/export_service.py` — CSV/HTML/PDF report generation
- `backend/models.py` — All Pydantic models
- `backend/config.py` — Settings from env vars

## Graph API Policy Endpoints (Beta)

All under `https://graph.microsoft.com/beta/`:

| Type | Endpoint |
|---|---|
| Device Configuration | `deviceManagement/deviceConfigurations` |
| Settings Catalog | `deviceManagement/configurationPolicies` |
| Compliance | `deviceManagement/deviceCompliancePolicies` |
| Compliance v2 | `deviceManagement/compliancePolicies` |
| App Protection | `deviceManagement/managedAppPolicies` |
| App Configuration | `deviceAppManagement/mobileAppConfigurations` |
| Endpoint Security | `deviceManagement/intents` |
| Conditional Access | `identity/conditionalAccessPolicies` |
| Autopilot | `deviceManagement/windowsAutopilotDeploymentProfiles` |
| PowerShell Scripts | `deviceManagement/deviceManagementScripts` |
| Remediation Scripts | `deviceManagement/deviceHealthScripts` |
| Group Policy (ADMX) | `deviceManagement/groupPolicyConfigurations` |

Assignments: `/{id}/assignments` for each policy (except Conditional Access which has inline conditions).

## Testing

- Backend: pytest with httpx async test client
- Frontend: Vitest + React Testing Library
- No tests against live Graph API — use mocked responses

## Implementation Order

1. Auth + Graph client
2. Policy fetcher (all 12 types)
3. Group resolver (with nested membership)
4. Dashboard + Group Explorer UI
5. Conflict analyzer
6. Optimization engine
7. Export service
