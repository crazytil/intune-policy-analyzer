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

## Windows executable — no Python or Node.js installation

The standalone build bundles the Python runtime, backend, and compiled frontend into
`IntunePolicyAnalyzer.exe`. Users only need a browser, network access to Microsoft,
and the tenant permissions listed below. No installer or administrator rights are
required by the app.

### Get a build using GitHub Actions

Once this workflow is in your repository's default branch:

1. Open **Actions → Build Windows executable → Run workflow**.
2. After it succeeds, download the **IntunePolicyAnalyzer-windows-x64** artifact.
3. Extract the ZIP and double-click `IntunePolicyAnalyzer.exe`.

The app opens in your default browser. Keep its console window open while using it;
press **Ctrl+C** in that window to stop the server. Closing the browser alone does
not stop it. The server binds only to `127.0.0.1`, using port 8099 by default.
The console prints the local address if the browser does not open automatically.

The executable is unsigned. SmartScreen, antivirus, or application-control policies
may require IT review, code signing, or allowlisting. **Bundling Python avoids an
installation requirement; it does not make the app Python-free or bypass a policy
that prohibits Python runtimes.** Ask IT to approve the application rather than
disabling security controls. The single-file executable extracts runtime files to
the user's temporary directory while running, which must permit execution.

The existing token cache is stored at
`%LOCALAPPDATA%\IntunePolicyAnalyzer\.token_cache.json`, not next to the executable.
It contains sensitive credentials and is not encrypted by the app; protect the
Windows user profile and use **Logout** to remove the cache. Tenant policy data
remains in memory. `INTUNE_TOKEN_CACHE_FILE` can override the cache location.

If port 8099 is occupied, use PowerShell to choose another port:

```powershell
$env:INTUNE_BACKEND_PORT = '8100'
.\IntunePolicyAnalyzer.exe
```

### Build locally (maintainers only)

Build on **Windows x64**, with Python 3.11 and Node.js 22 installed on the build
machine. End users do not need either dependency. From the repository root:

```powershell
py -3.11 -m venv backend/venv
backend/venv/Scripts/python.exe -m pip install -r backend/requirements-build.txt
npm --prefix frontend ci
npm --prefix frontend run build
backend/venv/Scripts/python.exe -m unittest discover -s tests
backend/venv/Scripts/python.exe -m PyInstaller --clean --noconfirm standalone.spec
```

Distribute `dist/IntunePolicyAnalyzer.exe`. The workflow uses these same build steps
and checks that the packaged executable serves the frontend, JavaScript, and API
from outside the source checkout. No live Graph requests are used in those checks.

PyInstaller builds for the OS it runs on; Linux cannot produce the Windows `.exe`.
The same spec can produce a native Linux executable using `backend/venv/bin/python`
instead. For source-based testing after building the frontend, run
`python backend/standalone.py --no-browser`. Omit `--no-browser` to open the browser.

## Prerequisites (running from source)

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
