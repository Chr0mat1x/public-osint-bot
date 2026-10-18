"""
sources/forums_public.py — публичные форумы и обсуждения.

Используем открытые API, не требующие авторизации:
  * Reddit public JSON  — /user/<name>/about.json и /search.json;
  * Hacker News (Algolia) — hn.algolia.com/api/v1/search;
  * Stack Exchange API 2.3 — /users?inname=... (публичный, без ключа).

Все три отдают только публичные данные. Если сервис блокирует датацентровые
IP (Reddit часто отвечает 403) — источник помечается как пропущенный.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import quote

from normalizer import Finding, Query, SourceResult

from .http_client import HttpClient, HttpError
from . import SourceContext

NAME = "forums_public"

REDDIT_ABOUT = "https://www.reddit.com/user/{name}/about.json"
REDDIT_SEARCH = "https://www.reddit.com/search.json"
HN_SEARCH = "https://hn.algolia.com/api/v1/search"
SE_USERS = "https://api.stackexchange.com/2.3/users"


async def collect(query: Query, ctx: SourceContext) -> SourceResult:
    if not query.username and not query.full_name:
        return SourceResult.skip(NAME, "нет username/имени — форумы пропущены.")

    findings: List[Finding] = []
    notes: List[str] = []

    # Каждый под-источник изолирован: падение одного не мешает остальным.
    # Лямбды, а не готовые корутины — иначе необработанная корутина останется висеть.
    sub_sources = (
        ("reddit", lambda: _reddit(query, ctx)),
        ("hackernews", lambda: _hackernews(query, ctx)),
        ("stackexchange", lambda: _stackexchange(query, ctx)),
    )
    for label, factory in sub_sources:
        try:
            findings.extend(await factory())
        except HttpError as exc:
            notes.append(f"{label}: {exc}")

    result = SourceResult(source=NAME, ok=True, findings=findings[: ctx.max_results])
    if notes and not findings:
        result.skipped = True
        result.error = "; ".join(sorted(set(notes))[:2])
    elif notes:
        result.error = "; ".join(sorted(set(notes))[:2])
    return result


# --------------------------------------------------------------------------- #
# Reddit
# --------------------------------------------------------------------------- #
async def _reddit(query: Query, ctx: SourceContext) -> List[Finding]:
    http: HttpClient = ctx.http
    findings: List[Finding] = []

    if query.username:
        data: Dict[str, Any] = await http.get_json(
            REDDIT_ABOUT.format(name=quote(query.username)),
            headers={"Accept": "application/json"},
        )
        user = (data.get("data") or {}) if isinstance(data, dict) else {}
        if user and not user.get("is_suspended"):
            findings.append(
                Finding(
                    source=NAME,
                    kind="profile",
                    url=f"https://www.reddit.com/user/{query.username}",
                    title=f"u/{user.get('name') or query.username}",
                    snippet=str(user.get("subreddit", {}).get("public_description") or "")[:400],
                    username=str(user.get("name") or query.username).lower(),
                    display_name=str(user.get("name") or ""),
                    extra={
                        "link_karma": user.get("link_karma", 0),
                        "comment_karma": user.get("comment_karma", 0),
                        "created_utc": user.get("created_utc", 0),
                    },
                )
            )

    term = query.username or query.full_name
    search: Dict[str, Any] = await http.get_json(
        REDDIT_SEARCH,
        params={"q": term, "limit": min(ctx.max_results, 15), "sort": "relevance", "type": "link"},
        headers={"Accept": "application/json"},
    )
    for child in ((search.get("data") or {}).get("children") or []):
        post = child.get("data") or {}
        permalink = str(post.get("permalink") or "")
        if not permalink:
            continue
        findings.append(
            Finding(
                source=NAME,
                kind="forum_post",
                url=f"https://www.reddit.com{permalink}",
                title=str(post.get("title") or "")[:150],
                snippet=str(post.get("selftext") or "")[:400],
                username=str(post.get("author") or "").lstrip("u/"),
                extra={"subreddit": post.get("subreddit") or "", "platform": "reddit"},
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Hacker News (Algolia, публичный API)
# --------------------------------------------------------------------------- #
async def _hackernews(query: Query, ctx: SourceContext) -> List[Finding]:
    http: HttpClient = ctx.http
    term = query.username or query.full_name
    data: Dict[str, Any] = await http.get_json(
        HN_SEARCH,
        params={"query": term, "hitsPerPage": min(ctx.max_results, 15), "tags": "(story,comment)"},
    )

    findings: List[Finding] = []
    for hit in (data.get("hits") or []):
        object_id = hit.get("objectID")
        if not object_id:
            continue
        is_comment = hit.get("comment_text") is not None
        url = (
            f"https://news.ycombinator.com/item?id={object_id}"
            if is_comment
            else str(hit.get("url") or f"https://news.ycombinator.com/item?id={object_id}")
        )
        findings.append(
            Finding(
                source=NAME,
                kind="forum_post",
                url=url,
                title=str(hit.get("title") or hit.get("story_title") or f"HN #{object_id}")[:150],
                snippet=str(hit.get("comment_text") or hit.get("story_text") or "")[:400],
                username=str(hit.get("author") or "").lower(),
                extra={
                    "points": hit.get("points") or 0,
                    "created_at": hit.get("created_at") or "",
                    "platform": "hackernews",
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Stack Exchange (публичный API, без ключа — дневная квота 300 запросов/IP)
# --------------------------------------------------------------------------- #
async def _stackexchange(query: Query, ctx: SourceContext) -> List[Finding]:
    http: HttpClient = ctx.http
    term = query.username or query.full_name
    data: Dict[str, Any] = await http.get_json(
        SE_USERS,
        params={
            "inname": term,
            "site": "stackoverflow",
            "pagesize": min(ctx.max_results, 15),
            "order": "desc",
            "sort": "reputation",
        },
    )

    findings: List[Finding] = []
    for user in (data.get("items") or []):
        link = str(user.get("link") or "")
        if not link:
            continue
        findings.append(
            Finding(
                source=NAME,
                kind="profile",
                url=link,
                title=str(user.get("display_name") or ""),
                snippet=f"Stack Overflow, репутация: {user.get('reputation', 0)}.",
                username=str(user.get("display_name") or "").lower(),
                display_name=str(user.get("display_name") or ""),
                extra={"reputation": user.get("reputation", 0), "platform": "stackoverflow"},
            )
        )
    return findings
