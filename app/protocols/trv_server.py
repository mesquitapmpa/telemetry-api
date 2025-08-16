# app/protocols/trv_server.py
import asyncio
import os
import logging

logger = logging.getLogger(__name__)

def _resolve_handler():
    """
    Busca no módulo app.protocols.trv uma coroutine handler(reader, writer).
    Tenta, na ordem: handler, gt06_server, gt06_handler.
    """
    from app.protocols import trv as trv_mod  # import tardio para evitar ciclos

    for name in ("handler", "gt06_server", "gt06_handler"):
        h = getattr(trv_mod, name, None)
        if h is not None:
            return h

    raise RuntimeError(
        "Nenhum handler encontrado em app.protocols.trv. "
        "Defina uma coroutine como handler/gt06_server/gt06_handler(reader, writer)."
    )

_trv_server: asyncio.AbstractServer | None = None  # referência global (opcional)

async def start_trv_server() -> asyncio.AbstractServer:
    """
    Cria e retorna um asyncio.Server usando o handler definido em app.protocols.trv.
    Porta definida por TRV_PORT (default 5010). Não dá serve_forever(); o loop do Uvicorn cuida.
    """
    global _trv_server
    if _trv_server is not None:
        return _trv_server

    handler = _resolve_handler()
    port = int(os.getenv("TRV_PORT", "5010"))
    _trv_server = await asyncio.start_server(handler, "0.0.0.0", port)
    addrs = ", ".join(str(s.getsockname()) for s in _trv_server.sockets)
    logger.info(f"[TRV] servidor GT06 escutando em {addrs}")
    return _trv_server

async def stop_trv_server() -> None:
    """Parada limpa (caso você prefira chamar explicitamente no shutdown)."""
    global _trv_server
    if _trv_server is None:
        return
    _trv_server.close()
    await _trv_server.wait_closed()
    logger.info("[TRV] servidor GT06 parado")
    _trv_server = None