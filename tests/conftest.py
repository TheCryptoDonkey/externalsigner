import os
from pathlib import Path

TEST_DATA = Path(__file__).parent / "data"
TEST_DATA.mkdir(exist_ok=True)
os.environ["LNBITS_DATA_FOLDER"] = str(TEST_DATA)
os.environ["DEBUG"] = "true"

import pytest_asyncio  # noqa: E402
from lnbits.core.crud import get_db_version  # noqa: E402
from lnbits.core.db import db as core_db  # noqa: E402
from lnbits.core.helpers import migrate_databases, run_migration  # noqa: E402
from lnbits.settings import settings  # noqa: E402

import externalsigner.migrations as ext_migrations  # noqa: E402
from externalsigner.crud import db  # noqa: E402
from externalsigner.services import runtime_state, set_transport  # noqa: E402


@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_databases():
    core_path = getattr(core_db, "path", None)
    if core_path and os.path.isfile(core_path):
        os.remove(core_db.path)
    await migrate_databases()
    extension_path = getattr(db, "path", None)
    if extension_path and os.path.isfile(extension_path):
        os.remove(db.path)
    current_version = await get_db_version("externalsigner")
    async with db.connect() as connection:
        await run_migration(
            connection,
            ext_migrations,
            "externalsigner",
            current_version,
        )


@pytest_asyncio.fixture(autouse=True)
async def reset_extension_state(init_databases):
    settings.debug = True
    await db.execute("DELETE FROM externalsigner.operations")
    await db.execute("DELETE FROM externalsigner.connections")
    set_transport(None)
    runtime_state.subscribed_pubkeys.clear()
    runtime_state.relays.clear()
    runtime_state.seen_event_ids.clear()
    runtime_state.next_refresh_at = 0
    yield
    set_transport(None)
