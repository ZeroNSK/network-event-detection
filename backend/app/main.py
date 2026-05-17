from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os

from .database import engine, Base
from .routers import auth, nodes, events, rules, incidents, logs, incident_access, event_access, node_access, rule_access, analysis, analytics, dataset
from .seed import seed_database
from .schema_migrations import ensure_runtime_schema


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events.
    """
    # Startup: Create database tables and seed data
    Base.metadata.create_all(bind=engine)
    ensure_runtime_schema()
    seed_database()
    yield
    # Shutdown: cleanup if needed
    pass


# Create FastAPI application
app = FastAPI(
    title="Network Security Monitoring System",
    description="REST API для системы обнаружения подозрительной активности в сети связи",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)


def get_cors_origins() -> list[str]:
    origins = os.getenv("CORS_ORIGINS")
    if origins:
        return [origin.strip() for origin in origins.split(",") if origin.strip()]
    return [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
    ]


LOCAL_NETWORK_ORIGIN_REGEX = (
    r"https?://(localhost|127\.0\.0\.1|10(?:\.\d{1,3}){3}|"
    r"192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})"
    r":(?:3000|3001)"
)


# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX", LOCAL_NETWORK_ORIGIN_REGEX),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api")
app.include_router(nodes.router, prefix="/api")
app.include_router(events.router, prefix="/api")
app.include_router(rules.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(incident_access.router, prefix="/api")
app.include_router(event_access.router, prefix="/api")
app.include_router(node_access.router, prefix="/api")
app.include_router(rule_access.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(analysis.router, prefix="/api")
app.include_router(analytics.router, prefix="/api")
app.include_router(dataset.router, prefix="/api")


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Network Security Monitoring System API",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
