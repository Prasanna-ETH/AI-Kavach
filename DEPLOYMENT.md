# 🚀 Cloud Deployment Guide: Render (Backend) & Vercel (Frontend)

This guide provides step-by-step instructions for deploying the **LLM Security Scanner** architecture to the cloud:
- **Backend API & Scanner Engine** $\rightarrow$ [Render](https://render.com) (Python Web Service or Docker)
- **Interactive Web Dashboard** $\rightarrow$ [Vercel](https://vercel.com) (React + Vite Single-Page Application)

---

## 🌐 Architecture in Production

```text
┌──────────────────────────────────────┐       HTTPS / SSE        ┌──────────────────────────────────────┐
│            VERCEL FRONTEND           │ ───────────────────────► │            RENDER BACKEND            │
│  • React 19 + Tailwind CSS Dashboard │ ◄─────────────────────── │  • FastAPI + Uvicorn ASGI Server     │
│  • Client-side routing via SPA       │      Live Telemetry      │  • Asynchronous Scanner Engine       │
│  • Hosted at *.vercel.app            │                          │  • 26 Embedded YAML Payload Packs    │
└──────────────────────────────────────┘                          │  • Dynamic CORS Configuration        │
                                                                  └──────────────────┬───────────────────┘
                                                                                     │
                                                                    Scans & Probes   ▼
                                                                  ┌──────────────────────────────────────┐
                                                                  │         TARGET AI / LLM APIs         │
                                                                  │  (OpenAI, Anthropic, Bedrock, etc.)  │
                                                                  └──────────────────────────────────────┘
```

---

## 📦 How the "Payloads in Local" Issue Was Solved

1. **Payloads are Bundled in the Backend Repo**:
   - The 26 YAML payload packs (under `scanner/payloads/`) are fully committed and tracked in git.
   - The backend includes a multi-tier path resolver (`scanner.config.PAYLOADS_DIR`, `os.environ["PAYLOADS_DIR"]`, and repo root fallbacks).
   - When deployed on Render, the backend serves all available payload packs to the frontend via the `GET /api/payload-packs` endpoint.
   - The frontend never needs to bundle raw payload files locally; it fetches them dynamically from your deployed Render backend.

2. **Dynamic CORS Support**:
   - The backend automatically permits all `*.vercel.app` domains (both preview branches and production domains) through regex matching (`allow_origin_regex=r"^https://.*\.vercel\.app$"`).
   - Custom frontend domains can be supplied via the `CORS_ORIGINS` environment variable.

3. **Client-Side Routing on Vercel**:
   - The `frontend/vercel.json` rewrites rule (`"/(.*)" -> "/index.html"`) ensures that direct page refreshes on `/findings`, `/live`, `/payloads`, and `/reports` will never return 404 errors.

---

## 🛠️ Step 1: Deploy Backend to Render

You can deploy the backend to Render using either **Option A (Native Python Web Service - Recommended)** or **Option B (Docker Container)**.

### Option A: Native Python Web Service (Recommended)

1. Sign in to your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** $\rightarrow$ **Web Service**.
3. Connect your GitHub repository (`Final-CTS---AI-LLM-Scanner` or your fork).
4. Configure the service settings:
   - **Name**: `llm-security-scanner-api` (or any name you prefer)
   - **Region**: Select the region closest to you (e.g., *Oregon (US West)* or *Frankfurt (EU)*)
   - **Branch**: `main`
   - **Root Directory**: *(Leave blank / empty — do NOT set to `backend`)*
   - **Runtime**: `Python 3`
   - **Build Command**:
     ```bash
     pip install -r requirements.txt
     ```
   - **Start Command**:
     ```bash
     uvicorn backend.api.main:app --host 0.0.0.0 --port $PORT
     ```
   - **Plan**: `Free`

5. **Add Environment Variables**:
   In the **Environment Variables** section, add:
   | Key | Value | Notes |
   |---|---|---|
   | `PYTHON_VERSION` | `3.11.9` | Ensures modern Python runtime |
   | `PYTHONPATH` | `.` | Ensures scanner and backend packages resolve |
   | `CORS_ORIGINS` | `*` | Or specify your Vercel URL once created |

6. Click **Create Web Service**.
7. Once deployed, Render will provide a public URL:
   `https://llm-security-scanner-api.onrender.com`
8. **Verify Backend Health**:
   Open `https://<your-render-app>.onrender.com/health` in your browser. You should receive:
   ```json
   {"status": "ok", "scanner": {"ok": true, "message": "scanner package imported successfully"}}
   ```
   Open `https://<your-render-app>.onrender.com/docs` to see the live Swagger API documentation.

---

### Option B: Docker Container Deployment

If you prefer containerized deployment:
1. Click **New +** $\rightarrow$ **Web Service**.
2. Select **Docker** as the environment (Render will automatically detect the root `Dockerfile`).
3. Set **Plan** to `Free` and click **Create Web Service**.

---

## ⚡ Step 2: Deploy Frontend to Vercel

1. Sign in to your [Vercel Dashboard](https://vercel.com).
2. Click **Add New...** $\rightarrow$ **Project**.
3. Import your GitHub repository (`Final-CTS---AI-LLM-Scanner`).
4. Configure the project settings:
   - **Project Name**: `llm-security-scanner`
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click **Edit** and select **`frontend`**
   - **Build Command**: `npm run build` (or leave default)
   - **Output Directory**: `dist` (or leave default)
   - **Install Command**: `npm install` (or leave default)

5. **Configure Environment Variables**:
   Under the **Environment Variables** section, add:
   | Key | Value |
   |---|---|
   | `VITE_API_URL` | `https://<your-render-app>.onrender.com` |

   *(Replace `<your-render-app>` with your actual Render service URL from Step 1 without trailing slash).*

6. Click **Deploy**.
7. In ~60 seconds, your site will be live at `https://<your-app>.vercel.app`.

---

## 🔍 Step 3: Verification & Sanity Checklist

1. **Dashboard & Payloads**:
   - Navigate to `https://<your-app>.vercel.app/payloads`.
   - You should see all **26 payload packs** loaded and ready to inspect (OWASP Top 10, agent evasion, handwritten packs, etc.).
2. **Interactive Scan**:
   - Go to **New Scan**.
   - Input a public or target API URL (or a cloud-hosted OpenAI/Anthropic/custom LLM endpoint).
   - Check the **I confirm I have authorization** checkbox and click **Launch Security Scan**.
3. **Live Telemetry (SSE)**:
   - Go to **Live Scan**.
   - Ensure the progress bar and real-time finding logs stream seamlessly from the Render backend.
4. **Reports**:
   - Click **Download HTML Report** or **Download JSON Report** on completed scans.

---

## 💡 Important Cloud Tips & FAQ

### 1. Render Free Tier Spin-Down (Cold Starts)
- On Render's Free tier, services spin down after 15 minutes of inactivity.
- The first request to your frontend after inactivity may take ~30–50 seconds while the backend spins up.
- **Tip**: You can use a free pinging service (like UptimeRobot or Cron-Job.org) to ping `https://<your-render-app>.onrender.com/health` every 10 minutes to keep it awake.

### 2. Ollama / Neural LLM-as-a-Judge on Cloud
- Ollama runs on `localhost:11434` when working locally.
- When running in cloud containers without a GPU, the scanner's evaluation engine uses the **calibrated heuristic and DLP rules** (Tier 0 & Tier 1) which consume **0 GPU resources** and **0 tokens**, running at sub-millisecond speeds.
- If you wish to use local LLM judging in cloud, you can point the Ollama endpoint in the UI to an external self-hosted Ollama or vLLM instance.

### 3. Playwright Headless Browser on Render
- For web chat scans using Playwright (`browser` target type), the native Python environment on Render's free tier lacks Chromium OS dependencies.
- REST API scans work 100% out-of-the-box on standard Render.
- If you need full headless browser testing on Render, deploy using **Option B (Docker Container)** and install Playwright's system dependencies.
