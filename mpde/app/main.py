import os
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

# Internal imports from our simplified flat layout
from app.api import router as api_router
from app.core import Base, engine, logger, settings
import app.models  # Required to register tables for SQLAlchemy

# ==========================================
# 1. LIFESPAN MANAGEMENT (Startup/Shutdown)
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles logic that needs to run before the server starts.
    In an enterprise setup, we ensure the DB schema is ready here.
    """
    logger.info("system_startup", message="Initializing MPDE Database...")
    try:
        # This creates the audit_logs table if it doesn't exist in mpde.db
        Base.metadata.create_all(bind=engine)
        logger.info("system_startup", status="Success", db_path=settings.DATABASE_URL)
    except Exception as e:
        logger.critical("system_startup_failed", error=str(e))
    
    yield
    # Logic for shutdown (e.g., closing connections) can go here
    logger.info("system_shutdown", message="MPDE service stopped.")

# ==========================================
# 2. APP INITIALIZATION
# ==========================================
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise-grade heuristic and behavioral URL analysis system.",
    version="1.0.0",
    lifespan=lifespan
)

# ==========================================
# 3. GLOBAL MIDDLEWARE
# ==========================================
# Allows your frontend dashboard to talk to your backend API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production in Lagos, replace with your specific domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 4. STATIC FILES & TEMPLATES
# ==========================================
# Ensure folders exist to prevent startup crashes
os.makedirs("app/static", exist_ok=True)
os.makedirs("app/templates", exist_ok=True)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# ==========================================
# 5. ROUTE REGISTRATION
# ==========================================
# This pulls in /api/v1/predict, /api/v1/health, and /api/v1/audit
app.include_router(api_router)

@app.get("/")
async def serve_dashboard(request: Request):
    """
    The main entry point for the Megadriod security team.
    Serves the UI where you'll paste URLs for analysis.
    """
    return templates.TemplateResponse(
    request=request,
    name="index.html",
    context={"title": "MPDE Dashboard"} 
    )

# ==========================================
# 6. ENTERPRISE ERROR HANDLING
# ==========================================
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catches any crash in the engine and returns a clean JSON error.
    Prevents the 'internal server error' from showing messy code logs to users.
    """
    logger.error("unhandled_exception", url=str(request.url), error=str(exc))
    return {
        "status": "error",
        "message": "The MPDE engine encountered an internal issue. Our team has been notified.",
        "incident_log_path": "/logs/audit.json"
    }

if __name__ == "__main__":
    import uvicorn
    # Start the server on port 8000
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
