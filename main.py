from fastapi import FastAPI
from app.infra.db import init_db
from app.interfaces.routes import router
from app.protocols.trv_server import start_trv_server  # <= AQUI
from app.routes.status_history import router as status_history_router

import os

app = FastAPI(title="Telemetry API")
app.include_router(router)
app.include_router(status_history_router)

if os.getenv("ENABLE_METRICS", "false").lower() == "true":
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator().instrument(app).expose(app)

@app.on_event("startup")
async def on_startup():
    await init_db()
    app.state.trv_server = await start_trv_server()

@app.on_event("shutdown")
async def on_shutdown():
    server = getattr(app.state, "trv_server", None)
    if server:
        server.close()
        await server.wait_closed()