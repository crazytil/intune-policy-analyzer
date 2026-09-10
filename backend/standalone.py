"""Local launcher for the bundled app (also usable from a source checkout)."""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import uvicorn


def configure_token_cache() -> None:
    # Never write credentials beside the executable or into its extraction folder.
    if "INTUNE_TOKEN_CACHE_FILE" not in os.environ:
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share")))
        directory = base / "IntunePolicyAnalyzer"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.environ["INTUNE_TOKEN_CACHE_FILE"] = str(directory / ".token_cache.json")


def create_app(web_directory: Path) -> FastAPI:
    if not (web_directory / "index.html").is_file():
        raise RuntimeError("Frontend build missing. Run npm ci && npm run build in frontend first.")

    from main import app as api

    app = FastAPI(title=api.title, version=api.version)
    app.include_router(api.router)
    # Last, so the UI cannot shadow API endpoints. StaticFiles rejects traversal.
    app.mount("/", StaticFiles(directory=web_directory, html=True), name="frontend")
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Intune Policy Analyzer locally")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    args = parser.parse_args()
    configure_token_cache()

    from config import settings

    root = Path(__file__).resolve().parent
    web = root / "web" if getattr(sys, "frozen", False) else root.parent / "frontend" / "dist"
    app = create_app(web)
    url = f"http://127.0.0.1:{settings.backend_port}"
    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=settings.backend_port,
        loop="asyncio", http="h11", ws="none", access_log=False,
    ))

    def open_when_ready() -> None:
        while not server.started and not server.should_exit:
            time.sleep(0.1)
        if server.started:
            webbrowser.open(url)

    if not args.no_browser:
        threading.Thread(target=open_when_ready, daemon=True).start()
    print(f"Intune Policy Analyzer: {url}\nKeep this window open. Press Ctrl+C to stop.", flush=True)
    server.run()


if __name__ == "__main__":
    main()
