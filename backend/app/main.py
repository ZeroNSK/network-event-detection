from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os
from pathlib import Path

from .database import engine, Base
from .routers import auth, nodes, events, rules, incidents, logs, incident_access, event_access, node_access, rule_access, analysis, analytics, dataset
from .seed import seed_database
from .schema_migrations import ensure_runtime_schema


PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIST_DIR = Path(
    os.getenv("FRONTEND_DIST_DIR", PROJECT_ROOT / "frontend" / "dist")
)
FRONTEND_INDEX = FRONTEND_DIST_DIR / "index.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan-контекст для действий при запуске и остановке приложения.
    """
    # При запуске создаем таблицы и загружаем демонстрационные данные.
    Base.metadata.create_all(bind=engine)
    ensure_runtime_schema()
    seed_database()
    yield
    # При остановке можно выполнить очистку ресурсов.
    pass


# Создаем приложение FastAPI.
app = FastAPI(
    title="Система мониторинга сетевой безопасности",
    description="REST API для системы обнаружения подозрительной активности в сети связи",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)


def _message_from_detail(detail) -> str:
    if isinstance(detail, dict):
        message = detail.get("message")
        return str(message) if message else "Ошибка запроса"
    if isinstance(detail, list):
        return "Ошибка валидации входных данных"
    return str(detail)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    detail = exc.detail
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={
            "code": f"HTTP_{exc.status_code}",
            "message": _message_from_detail(detail),
            "details": detail,
            "detail": detail,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = jsonable_encoder(exc.errors())
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "code": "VALIDATION_ERROR",
            "message": "Ошибка валидации входных данных",
            "details": errors,
            "detail": errors,
        },
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


# Настраиваем CORS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_origin_regex=os.getenv("CORS_ORIGIN_REGEX", LOCAL_NETWORK_ORIGIN_REGEX),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Подключаем роутеры.
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

if (FRONTEND_DIST_DIR / "assets").exists():
    app.mount(
        "/assets",
        StaticFiles(directory=FRONTEND_DIST_DIR / "assets"),
        name="frontend-assets",
    )


def frontend_build_available() -> bool:
    return FRONTEND_INDEX.exists()


@app.get("/")
async def root():
    """Root endpoint."""
    if frontend_build_available():
        return FileResponse(FRONTEND_INDEX)

    return {
        "message": "API системы мониторинга сетевой безопасности",
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_frontend(full_path: str):
    if not frontend_build_available():
        raise HTTPException(status_code=404, detail="Frontend build not found")

    requested_file = FRONTEND_DIST_DIR / full_path
    if requested_file.is_file():
        return FileResponse(requested_file)

    return FileResponse(FRONTEND_INDEX)
