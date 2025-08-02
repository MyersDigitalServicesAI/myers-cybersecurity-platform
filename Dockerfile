# render.yaml
# This file defines the "Infrastructure as Code" for the MyersCybersecurity platform on Render.
# It sets up three distinct services: the FastAPI backend, the Streamlit frontend,
# and the Stripe webhook handler.

# 1. Define a service group to share environment variables securely.
envVarGroups:
  - name: myers-cybersecurity-secrets
    envVars:
      - key: DATABASE_URL
        fromSecretFile: /etc/secrets/DATABASE_URL
      - key: JWT_SECRET_KEY
        fromSecretFile: /etc/secrets/JWT_SECRET_KEY
      - key: ENCRYPTION_KEY
        fromSecretFile: /etc/secrets/ENCRYPTION_KEY
      - key: STRIPE_SECRET_KEY
        fromSecretFile: /etc/secrets/STRIPE_SECRET_KEY
      - key: STRIPE_WEBHOOK_SECRET
        fromSecretFile: /etc/secrets/STRIPE_WEBHOOK_SECRET
      - key: PYTHON_VERSION
        value: "3.11" # Specify Python version

services:
  # 2. The FastAPI Backend Service (API)
  - type: web
    name: myers-cybersecurity-api
    env: python
    plan: starter # Choose a plan that fits your needs
    buildCommand: "pip install -r requirements.txt"
    startCommand: "uvicorn api_backend:app --host 0.0.0.0 --port $PORT"
    envVarGroup: myers-cybersecurity-secrets # Link the shared secrets
    healthCheckPath: /healthz
    autoDeploy: true # Automatically deploy on push to main branch

  # 3. The Streamlit Frontend Service (Dashboard)
  - type: web
    name: myers-cybersecurity-dashboard
    env: python
    plan: starter
    buildCommand: "pip install -r requirements.txt"
    startCommand: "streamlit run app.py --server.port $PORT --server.address 0.0.0.0"
    envVarGroup: myers-cybersecurity-secrets
    autoDeploy: true

  # 4. The Stripe Webhook Handler Service
  - type: web # Can also be a 'worker' type if it doesn't need a public URL
    name: myers-cybersecurity-webhooks
    env: python
    plan: starter
    buildCommand: "pip install -r requirements.txt"
    startCommand: "python webhook_handler.py" # This assumes the handler runs on its own
    envVarGroup: myers-cybersecurity-secrets
    autoDeploy: true

