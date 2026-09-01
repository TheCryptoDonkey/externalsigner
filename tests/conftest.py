import os
from pathlib import Path

TEST_DATA = Path(__file__).parent / "data"
TEST_DATA.mkdir(exist_ok=True)
os.environ["LNBITS_DATA_FOLDER"] = str(TEST_DATA)
os.environ["DEBUG"] = "true"

import pytest_asyncio  # noqa: E402
from lnbits.core import migrations as core_migrations  # noqa: E402
from lnbits.core.db import db as core_db  # noqa: E402
from lnbits.core.helpers import run_migration  # noqa: E402

import externalsigner.migrations as ext_migrations  # noqa: E402
from externalsigner.crud import db  # noqa: E402
from externalsigner.services import runtime_state, set_transport  # noqa: E402


@pytest_asyncio.fixture(scope="session", autouse=True)
async def init_databases():
    if os.path.isfile(core_db.path):
        os.remove(core_db.path)
    async with core_db.connect() as connection:
        await run_migration(connection, core_migrations, "core")
    if os.path.isfile(db.path):
        os.remove(db.path)
    async with db.connect() as connection:
        await run_migration(connection, ext_migrations, "externalsigner")


@pytest_asyncio.fixture(autouse=True)
async def reset_extension_state(init_databases):
    await db.execute("DELETE FROM externalsigner.operations")
    await db.execute("DELETE FROM externalsigner.connections")
    set_transport(None)
    runtime_state.subscribed_pubkeys.clear()
    runtime_state.relays.clear()
    runtime_state.seen_event_ids.clear()
    runtime_state.next_refresh_at = 0
    yield
    set_transport(None)
