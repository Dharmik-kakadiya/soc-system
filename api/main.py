import os
import sys
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# =========================
# Fix path to access ML pipeline and config
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.append(BASE_DIR)

from api.routes import health, predict

# Initialize FastAPI App
app = FastAPI(title="SOC System - IDS API", description="Real-time Intrusion Detection API")

# Add CORS so any Dashboard/Frontend can easily call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.responses import RedirectResponse

@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")

# =========================
# Include Routes
# =========================
app.include_router(health.router)
app.include_router(predict.router)

# To run this API, open a terminal and use:
# uvicorn api.main:app --host 0.0.0.0 --port 8001 --reload
