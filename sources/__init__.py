"""
sources/__init__.py — реестр источников и общий интерфейс.

Каждый источник — async-функция вида:

    async def collect(query: Query, ctx: SourceContext) -> SourceResult

Все источники обязаны работать только с публичными страницами без авторизации.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, List

from normalizer import Query, SourceResult

from .http_client import HttpClient


@dataclass
class SourceContext:
    """Общие зависимости, которые orchestrator передаёт в каждый источник."""

    http: HttpClient
    search_provider: str = "duckduckgo"
    search_api_key: str = ""
    github_token: str = ""
    max_results: int = 20


Collector = Callable[[Query, SourceContext], Awaitable[SourceResult]]


def get_collectors() -> List[tuple[str, Collector]]:
    """
    Импорт внутри функции: так не будет циклических импортов и лишних
    зависимостей, если какой-то источник не используется.
    """
    from .telegram_public import collect as telegram_collect
    from .search_engines import collect as search_collect
    from .github_public import collect as github_collect
    from .forums_public import collect as forums_collect

    return [
        ("telegram_public", telegram_collect),
        ("search_engines", search_collect),
        ("github_public", github_collect),
        ("forums_public", forums_collect),
    ]


__all__ = ["SourceContext", "Collector", "get_collectors", "HttpClient"]
