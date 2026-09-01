import asyncio

from fastapi import APIRouter
from lnbits.tasks import create_permanent_unique_task

from .crud import db
from .services import _log_exception, close_transport
from .tasks import start_nip46_runtime
from .views import externalsigner_generic_router
from .views_api import externalsigner_api_router

externalsigner_ext: APIRouter = APIRouter(prefix="/externalsigner", tags=["External Signer"])
externalsigner_ext.include_router(externalsigner_generic_router)
externalsigner_ext.include_router(externalsigner_api_router)

externalsigner_static_files = [{"path": "/externalsigner/static", "name": "externalsigner_static"}]

scheduled_tasks: list[asyncio.Task] = []


def externalsigner_start() -> None:
    task = create_permanent_unique_task("ext_externalsigner_nip46_runtime", start_nip46_runtime)
    scheduled_tasks.append(task)


def externalsigner_stop() -> None:
    for task in scheduled_tasks:
        try:
            task.cancel()
        except Exception as exc:
            _log_exception("Background task cancellation failed", exc)
    close_transport()


__all__ = [
    "db",
    "externalsigner_ext",
    "externalsigner_start",
    "externalsigner_static_files",
    "externalsigner_stop",
]
