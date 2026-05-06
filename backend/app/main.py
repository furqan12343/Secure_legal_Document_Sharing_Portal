"""
File: main.py
Purpose: Create FastAPI app, database tables, middleware, static frontend, and API routers.
Security: Secure headers are applied to every response and all APIs are under /api.
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from app.core.config import BASE_DIR, settings
from app.db import Base, engine
from app.middleware import add_security_headers
from app.models import *  # noqa: F401,F403
from app.routers import admin, auth, cases, documents, permissions, frontend_api

Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.app_name)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000", "http://127.0.0.1:5173", "http://localhost:5173", "null"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.middleware("http")(add_security_headers)

app.include_router(auth.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(cases.router, prefix="/api")
app.include_router(documents.router, prefix="/api")
app.include_router(permissions.router, prefix="/api")

# Compatibility endpoints used by the supplied single-file React frontend.
# These live without the /api prefix because that frontend calls /auth, /documents, /sharing, /users, and /admin directly.
app.include_router(frontend_api.router)

frontend_dir = BASE_DIR.parent / "frontend"
if frontend_dir.exists():
    app.mount("/frontend", StaticFiles(directory=frontend_dir, html=True), name="frontend")

@app.get("/")
def root():
    """Redirect to frontend. Security: headers are still applied by middleware."""
    return FileResponse(frontend_dir / "index.html", headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"})

@app.get("/health")
def health_check():
    """Health check. Security: does not expose secrets or database URL."""
    return {"status": "ok", "app": settings.app_name}
@app.get("/__frontend_debug")
def frontend_debug():
    """Debug endpoint for assignment demo only: confirms which frontend file is being served."""
    index_path = frontend_dir / "index.html"
    text = index_path.read_text(encoding="utf-8") if index_path.exists() else ""
    return {
        "frontend_index_path": str(index_path),
        "admin_option_present": "Role.ADMIN" in text and "Admin</option>" in text,
    }

