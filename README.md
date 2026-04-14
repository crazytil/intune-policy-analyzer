# Intune Policy Analyzer

A locally-run web application for analyzing Microsoft Intune policies. Find all policies that apply to a specific group, detect setting conflicts and overlaps, and get optimization recommendations — all without creating an app registration.

## Features

- **Group Explorer** — Select a group, see every policy assigned to it (including nested group inheritance and "All Users"/"All Devices"). Switch to reverse view: select a policy, see all target groups.
- **Conflict Analyzer** — Detect settings configured differently across policies targeting the same group. Red = conflict (different values), amber = duplicate (same value, multiple places).
- **Policy Optimization** — Find orphaned policies (empty/deleted groups), unused policies (no assignments), overly broad assignments, consolidation candidates, and redundant assignments.
- **Export** — CSV, HTML, and PDF reports for audit and governance.

## How It Works

```
Browser (localhost:5173)          Python Backend (localhost:8099)
┌─────────────────────┐          ┌──────────────────────────┐
│  React + TypeScript │◄────────►│  FastAPI + MSAL Python   │
│  Tailwind CSS       │  /api/*  │  Microsoft Graph API     │
└─────────────────────┘          └──────────────────────────┘
```

The backend authenticates using the **existing Microsoft Graph PowerShell enterprise app** (`14d82eec-204b-4c2f-b7e8-296a70dab67e`). No new app registration required — it uses your delegated permissions via interactive browser login.

## Supported Policy Types

- Device Configuration
- Settings Catalog
- Compliance Policies (v1 + v2)
- App Protection Policies
- App Configuration Policies
- Endpoint Security (Intents)
- Conditional Access
- Autopilot Deployment Profiles
- PowerShell Scripts
- Remediation Scripts (Proactive Remediations)
- Group Policy (ADMX)

## Prerequisites

- **Python 3.11+**
- **Node.js 18+**
- **Microsoft Graph PowerShell** — must have been used at least once in your tenant (creates the enterprise app)
- **Intune Administrator** or equivalent role (read access to all policy types)
- A browser for the interactive login flow

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/TBURG-IT/intune-policy-analyzer.git
cd intune-policy-analyzer
```

### 2. Set up the backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate    # macOS/Linux
# venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### 3. Set up the frontend

```bash
cd frontend
npm install
```

### 4. Run the application

```bash
# Option A: Use the start script
chmod +x start.sh
./start.sh

# Option B: Run manually
# Terminal 1 — Backend
cd backend && source venv/bin/activate && uvicorn main:app --reload --port 8099

# Terminal 2 — Frontend
cd frontend && npm run dev
```

### 5. Open the app

Navigate to `http://localhost:5173`. Click "Login" — a browser popup will authenticate you via Microsoft. Once logged in, click "Load Policies" to begin.

## Required Permissions (Delegated)

These scopes are requested at login via the Graph PowerShell enterprise app:

| Scope | Purpose |
|---|---|
| `DeviceManagementConfiguration.Read.All` | Read device configuration and compliance policies |
| `DeviceManagementManagedDevices.Read.All` | Read managed device information |
| `DeviceManagementServiceConfig.Read.All` | Read Intune service configuration |
| `Group.Read.All` | Read group information |
| `GroupMember.Read.All` | Resolve nested group memberships |
| `Directory.Read.All` | Read directory objects |
| `Policy.Read.All` | Read Conditional Access and other policies |

> **Note:** This tool is read-only. It never modifies any policies or configurations in your tenant.

## Security

- Runs entirely on localhost — no data sent to third parties
- Uses delegated auth — operates with your user's permissions only
- No app registration needed — reuses the existing Graph PowerShell enterprise app
- Token cache is stored locally and gitignored
- Uses Microsoft Graph Beta API

## License

MIT

## Contributing

Contributions welcome! Please read the design spec in `docs/specs/` before submitting changes.
