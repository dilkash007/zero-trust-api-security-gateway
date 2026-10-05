# Zero-Trust API Security & Behavioral Anomaly Engine - Backend

FastAPI backend service powering the Zero-Trust API Security Engine foundation.

## Prerequisites

- Python 3.11+
- PostgreSQL 14+ (Local or Remote)

## Setup Instructions

1. **Navigate to the backend directory**:
   ```bash
   cd backend
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # macOS / Linux
   # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   Copy `.env.example` to `.env` if not already present:
   ```bash
   cp .env.example .env
   ```
   Set your actual PostgreSQL connection string in `DATABASE_URL`:
   ```env
   DATABASE_URL=postgresql+psycopg2://postgres:YOUR_PASSWORD@localhost:5432/zero_trust_db
   ```

5. **Start the Development Server**:
   ```bash
   uvicorn app.main:app --reload
   ```
   The backend will start at `http://localhost:8000`.

## Endpoints (Step 1)

- `GET /health` - Service health status
- `GET /health/database` - Live PostgreSQL connectivity validation (returns 200 on success, 503 on failure)
- `GET /docs` - Swagger UI interactive documentation
