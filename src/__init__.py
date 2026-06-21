"""voidstrike package.

Load a local `.env` as early as possible — at package import, before any
submodule evaluates its module-level `os.environ.get(...)` defaults (gateway
`REDIS_URL`/`POSTGRES_URL`, agent `PG_URL`, models `LITELLM_*` / `OPENROUTER_*`,
etc.). Because this runs in `src/__init__.py`, it executes before any
`import src.<anything>` reaches those constants.

Real process env wins: `load_dotenv` defaults to `override=False`, so `.env`
only fills in vars that aren't already set. That keeps Docker compose
(env_file/environment) and explicitly-exported shell vars authoritative, while
local/dev runs get the `.env` values for free. Keep `.env.example` in sync when
adding new variables.
"""

import sys
from pathlib import Path

# Skip .env under pytest: tests must be deterministic and not inherit a
# developer's local `.env` (e.g. VOIDSTRIKE_USE_LITELLM / OPENROUTER_API_KEY,
# which change how models resolve). `pytest` is already in sys.modules by the
# time this package is first imported during collection.
if "pytest" not in sys.modules:
    try:
        from dotenv import load_dotenv

        _ROOT_ENV = Path(__file__).resolve().parent.parent / ".env"
        if _ROOT_ENV.exists():
            load_dotenv(_ROOT_ENV)
    except ImportError:
        # python-dotenv is a declared dependency; if it's somehow absent, fall
        # back to the process env rather than failing all imports.
        pass
