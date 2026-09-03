"""Static HTML for the dashboard and config console.

The pages are plain documents — all data is fetched client-side from the JSON
endpoints — so they are read verbatim, with no template engine involved.
"""

from __future__ import annotations

from functools import cache
from importlib import resources


@cache
def page(name: str) -> str:
    return resources.files("claude_cloak.web").joinpath(name).read_text(encoding="utf-8")


def dashboard_html() -> str:
    return page("dashboard.html")


def config_html() -> str:
    return page("config.html")
