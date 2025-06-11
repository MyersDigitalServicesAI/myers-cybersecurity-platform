# 🔐 Myers Cybersecurity Platform

Secure your business. Scale with confidence.

Myers Cybersecurity is an all-in-one, plug-and-play SaaS platform for startups and small businesses.

---

## 🚀 Quick Start

1. **Clone and install**
    ```sh
    git clone https://github.com/MyersDigitalServicesAI/myers-cybersecurity-platform.git
    cd myers-cybersecurity-platform
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

2. **Set up environment variables**
    - Copy `.env.example` to `.env` and fill in your secrets.

3. **Run locally**
    ```sh
    streamlit run app.py
    ```

---

## 🛠️ Tech Stack

- Streamlit (frontend)
- Python 3 (backend)
- Supabase PostgreSQL (database)
- Stripe (billing)
- SendGrid (email)
- Render.com (deployment)

---

## 🌐 Deploy

- One-click: **[Deploy to Render](https://render.com/)** (add your env vars in the dashboard)
- Or use Docker:
    ```sh
    docker build -t myers-cybersecurity .
    docker run --env-file .env -p 8501:8501 myers-cybersecurity
    ```

---

## 📬 Support

Questions? [Open an issue](https://github.com/MyersDigitalServicesAI/myers-cybersecurity-platform/issues)
