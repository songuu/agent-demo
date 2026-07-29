from __future__ import annotations

import uvicorn

from agent_platform.config import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "agent_platform.api.app:app",
        host="0.0.0.0",  # noqa: S104  # nosec B104 - network policy controls exposure.
        port=8080,
        proxy_headers=False,
        server_header=False,
        timeout_graceful_shutdown=settings.shutdown_grace_seconds,
    )


if __name__ == "__main__":
    main()
