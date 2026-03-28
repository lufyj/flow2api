import asyncio
import sqlite3

from src.core.database import Database


def test_init_db_creates_captcha_config_with_browser_max_solves_column(tmp_path):
    db_path = tmp_path / "flow.db"
    database = Database(str(db_path))

    asyncio.run(database.init_db())
    asyncio.run(database.init_config_from_toml({}, is_first_startup=True))

    with sqlite3.connect(db_path) as conn:
        columns = {
            row[1]: row for row in conn.execute("PRAGMA table_info(captcha_config)")
        }
        row = conn.execute(
            "SELECT browser_max_solves_per_browser FROM captcha_config WHERE id = 1"
        ).fetchone()

    assert "browser_max_solves_per_browser" in columns
    assert row == (10,)
