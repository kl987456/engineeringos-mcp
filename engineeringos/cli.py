"""Installed command-line entry point for the local stdio MCP server."""
from __future__ import annotations

import asyncio

from .server import app


def main() -> None:
    asyncio.run(app.run_stdio_async())


if __name__ == "__main__":
    main()
