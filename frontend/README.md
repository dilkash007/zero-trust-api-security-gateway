# Zero-Trust API Security & Behavioral Anomaly Engine - Frontend

Modern React + Vite frontend providing a SOC dashboard interface for the Zero-Trust API Security Engine.

## Tech Stack

- **React 18/19**
- **Vite**
- **Axios** (Centralized API client)
- **React Router DOM** (Client-side routing)
- **Vanilla CSS** (SOC Dark Theme with custom CSS design tokens)

## Setup & Running Locally

1. **Navigate to the frontend directory**:
   ```bash
   cd frontend
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start Development Server**:
   ```bash
   npm run dev
   ```
   The application will be accessible at `http://localhost:5173`.

## Features (Step 1 Foundation)

- Clean, responsive SOC security dashboard layout (`ZERO-TRUST SECURITY CENTER`)
- Centralized Axios client targeting `http://localhost:8000`
- Real-time diagnostics communicating with `GET /health` and `GET /health/database`
- Graceful offline/error handling when backend or database is unavailable
- Non-functional placeholders in the sidebar ready for upcoming modules (API Traffic, Threats, Attack Simulator, Policies)
