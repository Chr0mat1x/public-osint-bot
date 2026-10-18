"""
sources/github_public.py — публичный GitHub API.

Используем только публичные endpoints, доступные без авторизации:
  * GET /users/{username}                        — публичный профиль;
  * GET /search/users?q=...                      — поиск по логину/имени;
  * GET /search/repositories?q=user:{username}   — публичные репозитории.

GITHUB_TOKEN опционален: без него GitHub даёт 10 запросов/мин на поиск,
с токеном — 30. Токен нужен только для повышения лимита, доступ к приватным
данным не запрашивается.
"""

from __future__ import annotations

from typing import Any, Dict, List

from normalizer import Finding, Query, SourceResult

from .http_client import HttpError, HttpClient
from . import SourceContext

NAME = "github_public"
API = "https://api.github.com"


def _headers(token: str) -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def collect(query: Query, ctx: SourceContext) -> SourceResult:
    if not query.username:
        return SourceResult.skip(NAME, "username не распознан — GitHub-источник пропущен.")

    http: HttpClient = ctx.http
    headers = _headers(ctx.github_token)
    findings: List[Finding] = []
    notes: List[str] = []

    # 1. Публичный профиль по логину.
    try:
        user: Dict[str, Any] = await http.get_json(f"{API}/users/{query.username}", headers=headers)
        findings.append(_user_to_finding(user, query.username))
    except HttpError as exc:
        # 404 здесь — нормальная ситуация (нет такого логина), не ошибка источника.
        if exc.status != 404:
            notes.append(f"profile: {exc}")

    # 2. Публичные репозитории пользователя.
    try:
        repos: List[Dict[str, Any]] = await http.get_json(
            f"{API}/users/{query.username}/repos",
            params={"per_page": min(ctx.max_results, 20), "sort": "updated"},
            headers=headers,
        )
        for repo in repos or []:
            if repo.get("private"):
                # Приватные репозитории не показываем никогда, даже если API их отдал.
                continue
            findings.append(
                Finding(
                    source=NAME,
                    kind="repo",
                    url=str(repo.get("html_url") or ""),
                    title=str(repo.get("full_name") or repo.get("name") or ""),
                    snippet=str(repo.get("description") or ""),
                    username=query.username,
                    display_name=str(repo.get("full_name") or ""),
                    extra={
                        "stars": repo.get("stargazers_count", 0),
                        "language": repo.get("language") or "",
                        "updated": repo.get("updated_at") or "",
                    },
                )
            )
    except HttpError as exc:
        if exc.status != 404:
            notes.append(f"repos: {exc}")

    # 3. Поиск по логину/имени — помогает найти однофамильцев и связанные аккаунты.
    try:
        search: Dict[str, Any] = await http.get_json(
            f"{API}/search/users",
            params={"q": f"{query.username} in:login", "per_page": min(ctx.max_results, 10)},
            headers=headers,
        )
        for item in (search.get("items") or []):
            login = str(item.get("login") or "")
            if not login or login.lower() == query.username:
                continue
            findings.append(
                Finding(
                    source=NAME,
                    kind="profile",
                    url=str(item.get("html_url") or ""),
                    title=login,
                    snippet="Похожий логин в GitHub (возможный однофамилец).",
                    username=login.lower(),
                    display_name=login,
                    extra={"match_type": "similar_login"},
                )
            )
    except HttpError as exc:
        notes.append(f"search: {exc}")

    result = SourceResult(source=NAME, ok=True, findings=findings[: ctx.max_results])
    if notes and not findings:
        result.skipped = True
        result.error = "; ".join(sorted(set(notes))[:2])
    elif notes:
        result.error = "; ".join(sorted(set(notes))[:2])
    return result


def _user_to_finding(user: Dict[str, Any], username: str) -> Finding:
    return Finding(
        source=NAME,
        kind="profile",
        url=str(user.get("html_url") or f"https://github.com/{username}"),
        title=str(user.get("name") or user.get("login") or username),
        snippet=str(user.get("bio") or ""),
        username=str(user.get("login") or username).lower(),
        display_name=str(user.get("name") or ""),
        extra={
            "public_repos": user.get("public_repos", 0),
            "followers": user.get("followers", 0),
            "company": user.get("company") or "",
            "blog": user.get("blog") or "",
            "location": user.get("location") or "",
            "created_at": user.get("created_at") or "",
        },
    )
