"""``python -m keeper_control`` — run the control plane."""

from __future__ import annotations

import uvicorn

from .config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "keeper_control.app:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        # Reload only in development: it forks, which would double every
        # background job.
        reload=settings.environment == "development",
    )


if __name__ == "__main__":
    main()
