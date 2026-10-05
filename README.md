# Zero-Trust API Security & Behavioral Anomaly Engine

A modern, high-performance security platform designed to continuously verify API requests, establish behavioral baselines, detect anomalies, calculate dynamic risk scores, and enforce automated zero-trust mitigation policies.

---

## Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                           ZERO-TRUST SECURITY CENTER                              |
|                   (React + Vite + React Router + CSS Tokens)                      |
|                                                                                   |
|  [ Overview / SOC ]   [ API Traffic* ]   [ Threats* ]   [ Simulator* ]  [ Policy* ]|
+-----------------------------------------+-----------------------------------------+
                                          | Axios HTTP Client
                                          v
+-----------------------------------------------------------------------------------+
|                        FASTAPI CORE APPLICATION ENGINE                            |
|                                                                                   |
|  - CORS Security Middleware                                                       |
|  - Pydantic Settings Configuration Loader                                         |
|  - Centralized Health & Diagnostics Subsystem                                      |
|  - Future: Behavioral Baseline, Isolation Forest ML, Risk Engine, Gateway Proxy   |
+-----------------------------------------+-----------------------------------------+
                                          | SQLAlchemy 2.x SessionLocal
                                          v
+-----------------------------------------------------------------------------------+
|                            POSTGRESQL 18 DATABASE                                 |
|                                 (zero_trust_db)                                   |
+-----------------------------------------------------------------------------------+
* Placeholders reserved for future implementation steps.
```

---

## Technology Stack

### Backend
- **Python 3.11+**
- **FastAPI** — High-performance asynchronous web framework
- **Uvicorn** — ASGI production server
- **SQLAlchemy 2.x** — Python SQL toolkit and Object Relational Mapper
- **PostgreSQL 18** — Primary relational persistence engine
- **psycopg2-binary** — PostgreSQL database driver
- **Pydantic & Pydantic Settings** — Type validation and environment management
- **python-dotenv** — Environment configuration loader
- **FastAPI CORS Middleware** — Cross-Origin Resource Sharing control

### Frontend
- **React (JavaScript)** — UI component library
- **Vite** — Next-generation frontend build tool
- **Axios** — Centralized HTTP client
- **React Router DOM** — Declarative client-side routing
- **Vanilla CSS** — Custom SOC Dark Theme design system tokens (`--bg`, `--surface`, `--accent`, etc.)

---

## Project Structure

```
zero-trust-api-security/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   └── database/
│   │       ├── __init__.py
│   │       ├── connection.py
│   │       └── models.py
│   ├── .env
│   ├── .env.example
│   ├── requirements.txt
│   └── README.md
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   └── Sidebar.jsx
│   │   ├── pages/
│   │   │   └── Dashboard.jsx
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css
│   ├── index.html
│   ├── package.json
│   └── README.md
│
├── .gitignore
└── README.md
```

---

## Step 1 Scope vs Future Modules

### Step 1 Scope (Current)
- Clean, modular backend foundation with FastAPI and SQLAlchemy 2.x.
- Real PostgreSQL connection verification (`zero_trust_db`).
- Service health diagnostic endpoints (`/health` and `/health/database`).
- Clean, modular frontend with React, Vite, and React Router.
- SOC Dark Theme dashboard reporting live backend and database connectivity.
- Graceful offline error handling for disconnected states.

### Future Modules (Steps 2+)
- **Step 2**: Telemetry & API Request Logging (SQLAlchemy schemas and request logging middleware).
- **Step 3**: Behavioral Profiling & Baseline Engine (per-token/user request rate, endpoint distributions).
- **Step 4**: Anomaly Detection Engine (Machine Learning with Isolation Forest / Statistical Outlier models).
- **Step 5**: Risk Scoring & Dynamic Policy Decision Engine (ALLOW, MONITOR, RATE_LIMIT, CHALLENGE, BLOCK).
- **Step 6**: Reverse Proxy / API Gateway Middleware enforcement.
- **Step 7**: Attack Simulator & Interactive Security Center UI controls.

---

## Installation & Setup

### 1. PostgreSQL Database Setup
Ensure PostgreSQL is running locally on port 5432 and create the database `zero_trust_db`:

```bash
# Using psql command line
psql -U postgres -c "CREATE DATABASE zero_trust_db;"
```

### 2. Backend Setup & Configuration

1. Change directory to `backend`:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables in `backend/.env`:
   ```bash
   cp .env.example .env
   ```
   Edit `backend/.env` with your PostgreSQL password:
   ```env
   DATABASE_URL=postgresql+psycopg2://postgres:YOUR_PASSWORD@localhost:5432/zero_trust_db
   ```

5. Start the backend development server:
   ```bash
   uvicorn app.main:app --reload
   ```
   The backend will be available at `http://localhost:8000`.

### 3. Frontend Setup & Run

1. Open a new terminal and navigate to `frontend`:
   ```bash
   cd frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```
   The frontend dashboard will be available at `http://localhost:5173`.

---

## Testing Commands & Verification

### Step 1 Automated Verification Matrix

| Test # | Objective | Command / Procedure | Expected Result |
|--------|-----------|---------------------|-----------------|
| **TEST 1** | Service Health | `curl -i http://localhost:8000/health` | HTTP 200, `{"status": "ok", "service": "zero-trust-api-security", "version": "0.1.0"}` |
| **TEST 2** | Database Health | `curl -i http://localhost:8000/health/database` | HTTP 200, `{"status": "ok", "database": "connected"}` |
| **TEST 3** | Interactive Docs | Open `http://localhost:8000/docs` in browser | FastAPI Swagger UI interactive documentation loads |
| **TEST 4** | React Dashboard | Open `http://localhost:5173` in browser | ZERO-TRUST SECURITY CENTER dashboard loads |
| **TEST 5** | Frontend Service Check | Check Dashboard Card 2 | "Backend Connected" displayed with real data |
| **TEST 6** | Frontend Database Check | Check Dashboard Card 3 | "PostgreSQL Connected" displayed with real data |
| **TEST 7** | Database Failure Handling | Temporarily set invalid DB credentials or stop DB | `/health/database` returns HTTP 503; frontend displays "Database unavailable" |
| **TEST 8** | Backend Failure Handling | Stop backend server | Frontend displays "Backend unavailable" |
