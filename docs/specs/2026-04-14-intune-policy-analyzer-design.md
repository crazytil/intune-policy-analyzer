# Intune Policy Analyzer — Design Spec

**Date:** 2026-04-14
**Status:** Approved
**Focus:** Group-centric policy analysis + policy hygiene/optimization

---

## Problem

Managing Intune at scale means hundreds of policies across 12+ policy types, assigned to dozens of groups with nested memberships. Admins lack visibility into:

- Which policies actually hit a specific group (including inheritance)
- Where settings conflict or duplicate across policies targeting the same groups
- Orphaned, unused, overly broad, or redundant policy assignments

Existing tools (IntuneDiff, IntuneManagement) focus on policy comparison and export/import. None provide a **group-centric** view with full inheritance resolution and optimization recommendations.

---

## Solution

A locally-run web application (React + Python FastAPI) that connects to Microsoft Graph API using the existing Microsoft Graph PowerShell enterprise app (no new app registration required) and provides:

1. **Bidirectional Group Explorer** — Group → Policies and Policy → Groups with nested group inheritance
2. **Conflict Analyzer** — Detect settings configured differently across policies hitting the same group
3. **Optimization Engine** — Identify orphaned, unused, overly broad, consolidatable, and redundant policies
4. **Export** — CSV, HTML, PDF reports

---

## Architecture

```
Browser (localhost:5173)          Python Backend (localhost:8099)
┌─────────────────────┐          ┌──────────────────────────┐
│  React + Vite + TS  │◄────────►│  FastAPI + MSAL Python   │
│  Tailwind CSS       │  /api/*  │                          │
│                     │          │  ► Auth (Graph PS app ID) │
│  Views:             │          │  ► Graph Client (async)   │
│  • Dashboard        │          │  ► Policy Fetcher         │
│  • Group Explorer   │          │  ► Assignment Resolver    │
│  • Policy Explorer  │          │  ► Conflict Analyzer      │
│  • Optimization     │          │  ► Optimization Engine    │
│  • Export           │          │  ► Group Resolver         │
└─────────────────────┘          └──────────┬───────────────┘
                                            │
                                 Microsoft Graph API (Beta)
                                 ├─ deviceManagement/*
                                 ├─ groups/*
                                 └─ identity/conditionalAccess/*
```

### Authentication

- MSAL Python with interactive browser flow
- Uses the well-known Microsoft Graph PowerShell client ID: `14d82eec-204b-4c2f-b7e8-296a70dab67e`
- **No new app registration required** — piggybacks on the existing "Microsoft Graph Command Line Tools" enterprise app
- Delegated permissions only — operates with the signed-in user's permissions
- Token cached locally in `.token_cache.json` (gitignored)

### Required Delegated Scopes

- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `DeviceManagementServiceConfig.Read.All`
- `Group.Read.All`
- `GroupMember.Read.All`
- `Directory.Read.All`
- `Policy.Read.All`

---

## Supported Policy Types

| # | Policy Type | Graph API Endpoint (Beta) | Settings Sub-endpoint |
|---|---|---|---|
| 1 | Device Configuration | `/deviceManagement/deviceConfigurations` | Inline properties |
| 2 | Settings Catalog | `/deviceManagement/configurationPolicies` | `/{id}/settings` |
| 3 | Compliance Policies | `/deviceManagement/deviceCompliancePolicies` | Inline properties |
| 4 | Compliance Policies v2 | `/deviceManagement/compliancePolicies` | `/{id}/settings` |
| 5 | App Protection | `/deviceManagement/managedAppPolicies` | Inline properties |
| 6 | App Configuration | `/deviceAppManagement/mobileAppConfigurations` | Inline properties |
| 7 | Endpoint Security | `/deviceManagement/intents` | `/{id}/categories` + settings |
| 8 | Conditional Access | `/identity/conditionalAccessPolicies` | Inline `conditions`/`grantControls` |
| 9 | Autopilot Profiles | `/deviceManagement/windowsAutopilotDeploymentProfiles` | Inline properties |
| 10 | PowerShell Scripts | `/deviceManagement/deviceManagementScripts` | Inline properties |
| 11 | Remediation Scripts | `/deviceManagement/deviceHealthScripts` | Inline properties |
| 12 | Group Policy (ADMX) | `/deviceManagement/groupPolicyConfigurations` | `/{id}/definitionValues` |

All policy types fetched in parallel via `asyncio.gather()` with semaphore-controlled concurrency to avoid Graph API rate limits.

---

## Core Features

### Feature 1: Policy Ingestion

- Fetches all 12 policy types in parallel
- For each policy: fetches assignments via `/{id}/assignments`
- For each policy: fetches detailed settings via type-specific sub-endpoints
- Caches results in memory for the session (re-fetch on demand)
- Progress bar in the UI during ingestion

### Feature 2: Group Explorer (Bidirectional + Inheritance)

**Group → Policies direction:**
- Search/autocomplete for groups
- For the selected group, show every policy assigned to it:
  - Direct assignments (group is explicitly in the assignment)
  - Inherited assignments (group is a nested member of an assigned group)
  - "All Users" / "All Devices" assignments
- Organized by policy type with expandable settings
- Conflict indicators inline (red/amber badges)
- Toggle to show/hide inherited assignments

**Policy → Groups direction:**
- Select a policy, see all groups it targets
- Shows assignment type: Include vs Exclude
- Shows any assignment filters applied

**Nested group resolution:**
- Uses `/groups/{id}/transitiveMembers` for group membership chains
- Uses `/groups/{id}/transitiveMemberOf` for parent group resolution
- Caches group hierarchy to avoid redundant API calls

### Feature 3: Conflict & Overlap Analysis

- Extracts individual settings from each policy type into normalized format:
  ```json
  { "settingKey": "...", "value": "...", "policyId": "...", "policyType": "...", "policyName": "..." }
  ```
- Groups by setting key across all policies hitting the same group
- Classification:
  - **Conflict (red):** Same setting, different values, same target group
  - **Duplicate (amber):** Same setting, same value, multiple policies
- Shows effective value based on Intune precedence rules
- Per-group or tenant-wide analysis

### Feature 4: Optimization Engine

| Finding | Description | Severity |
|---|---|---|
| Orphaned policies | Assigned to groups that are empty or deleted | High |
| Unused policies | No assignments at all | Medium |
| Overly broad | Assigned to "All Users"/"All Devices" — flags actual member count | Medium |
| Consolidation candidates | Policies targeting the same group with no conflicts | Low |
| Redundant assignments | Same policy assigned via both parent and child group | Low |

- Each finding includes a plain-English recommendation
- Optimization score (0-100) on the dashboard

### Feature 5: Export

- CSV, HTML, PDF for each view
- Respects current filters before export
- Report includes: timestamp, tenant info, user who ran the analysis

---

## UI Layout

### Tab 1: Dashboard
- Login status + tenant info
- Summary cards: Total policies, total groups with assignments, conflicts found, optimization score
- "Load Policies" button with progress bar

### Tab 2: Group Explorer
- Search bar with autocomplete at top
- Left panel: group list with member counts and assignment counts
- Right panel: policies for selected group, organized by type
- Expandable rows for settings detail
- Red/amber badges for conflicts/duplicates
- Toggle: show/hide inherited assignments
- Button: switch to Policy → Groups mode

### Tab 3: Conflict Analyzer
- Stats bar: total overlaps, conflicts, duplicates, affected policies
- Filter chips: All / Conflicts Only / Duplicates Only
- Searchable table with expandable rows
- Side-by-side value comparison with diff highlighting

### Tab 4: Optimization
- Sub-tabs: Orphaned | Overly Broad | Consolidation | Unused | Redundant
- Table per sub-tab with severity indicators
- Recommendations column
- "Export Report" button (CSV / HTML / PDF)

### Design Language
- Clean, professional admin tool aesthetic
- Dark/light mode toggle
- Minimal color: red (conflict), amber (duplicate), green (clean)
- No glassmorphism or decorative elements

---

## Project Structure

```
intune-policy-analyzer/
├── backend/
│   ├── main.py                 # FastAPI app, CORS, all API routes
│   ├── auth.py                 # MSAL delegated auth (Graph PS client ID)
│   ├── graph_client.py         # Async httpx client, token refresh, pagination
│   ├── policy_fetcher.py       # 12 policy types, assignments, settings detail
│   ├── group_resolver.py       # Nested group resolution, transitive membership
│   ├── conflict_analyzer.py    # Setting normalization, conflict/duplicate detection
│   ├── optimization_engine.py  # Orphaned, broad, consolidation, unused, redundant
│   ├── export_service.py       # CSV/HTML/PDF generation
│   ├── models.py               # Pydantic models
│   ├── config.py               # Environment-based settings
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── GroupExplorer.tsx
│   │   │   ├── ConflictAnalyzer.tsx
│   │   │   └── Optimization.tsx
│   │   ├── services/
│   │   │   └── api.ts          # Backend API client
│   │   ├── types/
│   │   │   └── index.ts        # TypeScript interfaces
│   │   └── App.tsx
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   ├── tailwind.config.js
│   └── vite.config.ts
├── docs/
│   └── specs/
│       └── 2026-04-14-intune-policy-analyzer-design.md
├── AGENTS.md
├── README.md
├── .gitignore
└── start.sh
```

---

## Implementation Phases

### Phase 1 — MVP
- Auth (MSAL + Graph PS client ID)
- Policy ingestion (all 12 types with assignments and settings)
- Group Explorer (bidirectional with inheritance)
- Dashboard with summary

### Phase 2 — Analysis
- Conflict analyzer (per-group and tenant-wide)
- Setting normalization across policy types

### Phase 3 — Optimization & Export
- Optimization engine (all 5 finding types)
- Export service (CSV/HTML/PDF)
- Optimization score

---

## Security Notes

- Runs locally only — no data leaves your machine except to Microsoft Graph
- Token cache (`.token_cache.json`) is gitignored
- Read-only scopes — the tool never modifies policies
- Uses Graph API Beta — endpoints may change without notice

---

## Non-Goals (Explicit)

- No policy editing/creation — this is read-only analysis
- No AI/LLM integration — plain deterministic analysis
- No multi-tenant support in MVP
- No cloud deployment in MVP
