# CyberGrid Controller

CyberGrid Controller is a reference implementation of a cybersecurity-enabled smart controller for microgrids.  
It combines operational telemetry collection, security monitoring, patch orchestration, and a lightweight operator UI.

## Features

- **Flask API** powering authentication, telemetry, IDS/IPS events, patch rollout, and grid control endpoints.
- **Role-based access control** with JWT access/refresh tokens (`admin`, `analyst`, `operator`, `viewer`).
- **Hybrid IDS/IPS** combining rule heuristics, statistical deviation checks, and on-demand attack simulations.
- **Patch management simulator** that inventories components, validates payload signatures, and records rollout outcomes.
- **Relational persistence** (SQLAlchemy + SQLite) for users, telemetry, security events, and patch status.
- **Rich dashboard** featuring a multi-page layout: overview landing plus telemetry, security, and admin workspaces.
- **User administration** – admins can create users, adjust roles, and toggle account status directly from the UI.
- **Attack simulations** – admins and analysts can launch canned attack scenarios to verify that the IPS issues mitigation events.

## Navigation

- `index.html` – Overview landing page with login, session banner, and grid activity snapshot.
- `telemetry.html` – Live charting for voltage/frequency with pause/resume controls.
- `security.html` – Security event feed and incident simulation tools (analyst/admin).
- `admin.html` – Role and account lifecycle management (admin only).

## Project Structure

```
cybergrid-controller/
├── backend/              Flask application and supportive modules
├── frontend/             Static dashboard
├── database/             SQL schema bootstrap scripts
├── test_data/            Microgrid telemetry samples for IDS ingestion
├── requirements.txt      Python dependencies
└── README.md
```

## Getting Started

1. **Install dependencies**

   ```bash
   python -m venv .venv
   .venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```

2. **Initialize the database**

   ```bash
   python -c "from backend.models import init_db; init_db()"
   python -c "from backend.auth import create_user; create_user('admin', 'AdminPass123!', role='admin')"
   ```

3. **Run the backend**

   ```bash
   flask --app backend.app:app run
   ```

   The API will listen on `http://127.0.0.1:5000`.

4. **Open the dashboard**

   Browse to `http://127.0.0.1:5000/` and sign in with an account (the backend serves the frontend assets).

   Once authenticated as an admin you can provision additional `analyst`, `operator`, or `viewer` accounts from the dashboard.

## API Overview

- `POST /auth/login`