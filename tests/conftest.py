import os


# Ensure app.db can be imported in unit tests.
# The app requires IDS_DATABASE_URL at import time; use a local sqlite file for pytest.
_DB_URL = os.environ.get("IDS_DATABASE_URL") or "sqlite+pysqlite:///./.pytest_ids.sqlite"
os.environ.setdefault("IDS_DATABASE_URL", _DB_URL)

# Make DB pool small for sqlite (and for faster, deterministic tests).
os.environ.setdefault("IDS_DB_POOL_SIZE", "1")
os.environ.setdefault("IDS_DB_MAX_OVERFLOW", "0")
os.environ.setdefault("IDS_DB_POOL_TIMEOUT", "5")
os.environ.setdefault("IDS_DB_POOL_RECYCLE", "3600")


def _patch_config_database_url() -> None:
    try:
        import app.config as _cfg

        # Config.DATABASE_URL is read at import time; keep it in sync for tests.
        try:
            _cfg.Config.DATABASE_URL = os.environ.get("IDS_DATABASE_URL")
        except Exception:
            pass
        try:
            _cfg.config.DATABASE_URL = os.environ.get("IDS_DATABASE_URL")
        except Exception:
            pass
    except Exception:
        pass


_patch_config_database_url()


def pytest_configure(config):  # noqa: D401
    _patch_config_database_url()


def pytest_sessionstart(session):
    # Create tables for modules that persist alerts/correlation info.
    try:
        import app.models.db_models  # noqa: F401
        from app.db import init_db

        init_db()
    except Exception:
        # Unit tests should still run even if DB init fails.
        pass
