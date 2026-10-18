"""
sources/search_engines.py — поисковые системы.

Поддерживаемые провайдеры (search.provider в config.yaml):

  auto        (по умолчанию) — пробует duckduckgo, при блокировке/капче
                автоматически переключается на bing_html. Ключ не нужен.
  duckduckgo  — публичная HTML-выдача html.duckduckgo.com (без ключа).
                С датацентровых IP часто отдаёт анти-бот челлендж — тогда
                источник честно помечается как пропущенный.
  bing_html   — публичная HTML-выдача bing.com (без ключа).
  serpapi     — официальный API SerpAPI, нужен SEARCH_API_KEY.
  bing        — Azure Bing Web Search API, нужен SEARCH_API_KEY.

Авторизация нигде не используется, капчи не решаются: при челлендже источник
пропускается (в режиме auto — с фолбэком на другой движок).
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from typing import Any, Dict, List
from urllib.parse import unquote

from normalizer import Finding, Query, SourceResult, url_host, username_from_profile_url

from .http_client import HttpError
from . import SourceContext

NAME = "search_engines"

DDG_HTML = "https://html.duckduckgo.com/html/"
BING_HTML = "https://www.bing.com/search"
SERPAPI = "https://serpapi.com/search.json"
BING_API = "https://api.bing.microsoft.com/v7.0/search"

# Порядок провайдеров в режиме auto: первый сработавший и выигрывает.
AUTO_CHAIN = ("duckduckgo", "bing_html")

# Разбор результатов DuckDuckGo HTML.
DDG_RESULT_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
DDG_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(?P<snippet>.*?)</a>', re.IGNORECASE | re.DOTALL
)

# Разбор результатов Bing HTML: заголовок — в <h2><a href="...">, сниппет — в <p>.
BING_BLOCK_RE = re.compile(r'<li class="b_algo".*?(?=<li class="b_algo"|</ol>)', re.DOTALL)
BING_LINK_RE = re.compile(
    r'<h2[^>]*>\s*<a[^>]+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
BING_SNIPPET_RE = re.compile(r"<p[^>]*>(?P<snippet>.*?)</p>", re.IGNORECASE | re.DOTALL)

TAGS_RE = re.compile(r"<[^>]+>")

# Признаки анти-бот челленджа в HTML-выдаче (DuckDuckGo отдаёт anomaly.js).
CHALLENGE_MARKERS = ("anomaly.js", "cc=botnet", "challenge-form", "/anomaly/")


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(TAGS_RE.sub(" ", value or ""))).strip()


def _unwrap_ddg_url(href: str) -> str:
    """DuckDuckGo оборачивает ссылки в /l/?uddg=<urlencoded> — разворачиваем."""
    if "uddg=" in href:
        match = re.search(r"uddg=([^&]+)", href)
        if match:
            return unquote(match.group(1))
    if href.startswith("//"):
        return "https:" + href
    return href


def _unwrap_bing_url(href: str) -> str:
    """
    Bing оборачивает ссылки в /ck/a?...&u=a1<base64url>.
    Разворачиваем base64; если не вышло — возвращаем как есть.
    """
    href = html.unescape(href)
    match = re.search(r"[?&]u=a1([^&]+)", href)
    if not match:
        return href

    raw = unquote(match.group(1))
    padded = raw + "=" * (-len(raw) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return href
    return decoded if decoded.startswith("http") else href


def _assert_no_challenge(page: str, provider: str) -> None:
    """Анти-бот челлендж — это не «ноль результатов», а блокировка движка."""
    lowered = page[:6000].lower()
    if any(marker in lowered for marker in CHALLENGE_MARKERS):
        raise HttpError(
            f"{provider}: анти-бот челлендж, источник пропущен (капча не решается).",
            kind="captcha",
        )


def build_queries(query: Query) -> List[str]:
    """Набор поисковых запросов: по username, по имени и по «username + имя»."""
    queries: List[str] = []
    if query.username:
        queries.append(f'"{query.username}"')
    if query.full_name:
        queries.append(f'"{query.full_name}"')
    if query.username and query.full_name:
        queries.append(f'"{query.username}" "{query.full_name}"')
    return queries or [query.raw]


def _resolve_chain(provider: str, api_key: str) -> List[str]:
    """
    Определяет, какие движки реально опрашивать.
    auto — идём по цепочке, пока не получим непустой результат.
    """
    provider = (provider or "auto").lower()

    if provider == "auto":
        return list(AUTO_CHAIN)
    if provider == "bing" and not api_key:
        # Выбран Azure Bing, но ключа нет — используем публичную HTML-выдачу.
        return ["bing_html"]
    return [provider]


async def collect(query: Query, ctx: SourceContext) -> SourceResult:
    chain = _resolve_chain(ctx.search_provider, ctx.search_api_key)
    findings: List[Finding] = []
    notes: List[str] = []

    for provider in chain:
        provider_findings: List[Finding] = []

        for search_query in build_queries(query):
            try:
                provider_findings.extend(await _run_provider(provider, search_query, ctx))
            except HttpError as exc:
                # Капча/блокировка/таймаут одного запроса не роняют источник.
                notes.append(str(exc))
                break

            if len(provider_findings) >= ctx.max_results:
                break

        if provider_findings:
            findings.extend(provider_findings)
            # В режиме auto первый сработавший движок закрывает вопрос.
            if ctx.search_provider.lower() == "auto":
                break
        else:
            notes.append(f"{provider}: выдача пуста")

        if len(findings) >= ctx.max_results:
            break

    result = SourceResult(source=NAME, ok=True, findings=findings[: ctx.max_results])
    if not findings:
        # Пусто из-за блокировок/челленджей — помечаем источник пропущенным с причиной,
        # чтобы в отчёте было видно: это не «ничего не найдено», а «поиск не отработал».
        result.skipped = bool(notes)
        result.error = "; ".join(dict.fromkeys(notes))[:300] if notes else "поисковики не вернули результатов"
    elif notes:
        result.error = "; ".join(dict.fromkeys(notes))[:300]
    return result


async def _run_provider(provider: str, search_query: str, ctx: SourceContext) -> List[Finding]:
    if provider == "serpapi":
        return await _serpapi(search_query, ctx)
    if provider == "bing":
        return await _bing_api(search_query, ctx)
    if provider == "bing_html":
        return await _bing_html(search_query, ctx)
    return await _duckduckgo(search_query, ctx)


# --------------------------------------------------------------------------- #
# Провайдеры без ключа
# --------------------------------------------------------------------------- #
async def _duckduckgo(search_query: str, ctx: SourceContext) -> List[Finding]:
    http = ctx.http
    # html-версия ожидает POST; GET отдаёт форму без выдачи.
    page = await http.request("POST", DDG_HTML, data={"q": search_query, "kl": "wt-wt"})
    _assert_no_challenge(page, "duckduckgo")

    links = list(DDG_RESULT_RE.finditer(page))
    snippets = [_clean(m.group("snippet")) for m in DDG_SNIPPET_RE.finditer(page)]

    findings: List[Finding] = []
    for index, match in enumerate(links[: ctx.max_results]):
        url = _unwrap_ddg_url(html.unescape(match.group("href")))
        findings.append(
            Finding(
                source=NAME,
                kind="profile" if username_from_profile_url(url) else "post",
                url=url,
                title=_clean(match.group("title")),
                snippet=snippets[index] if index < len(snippets) else "",
                username=username_from_profile_url(url),
                extra={"engine": "duckduckgo", "query": search_query, "host": url_host(url)},
            )
        )
    return findings


async def _bing_html(search_query: str, ctx: SourceContext) -> List[Finding]:
    http = ctx.http
    page = await http.get_text(
        BING_HTML,
        params={"q": search_query, "count": min(ctx.max_results, 20), "setlang": "en"},
    )
    _assert_no_challenge(page, "bing_html")

    findings: List[Finding] = []
    for block in BING_BLOCK_RE.findall(page):
        link = BING_LINK_RE.search(block)
        if not link:
            continue
        url = _unwrap_bing_url(link.group("href"))
        if not url.startswith("http"):
            continue

        snippet_match = BING_SNIPPET_RE.search(block)
        findings.append(
            Finding(
                source=NAME,
                kind="profile" if username_from_profile_url(url) else "post",
                url=url,
                title=_clean(link.group("title")),
                snippet=_clean(snippet_match.group("snippet")) if snippet_match else "",
                username=username_from_profile_url(url),
                extra={"engine": "bing_html", "query": search_query, "host": url_host(url)},
            )
        )
        if len(findings) >= ctx.max_results:
            break
    return findings


# --------------------------------------------------------------------------- #
# Провайдеры по ключу
# --------------------------------------------------------------------------- #
async def _serpapi(search_query: str, ctx: SourceContext) -> List[Finding]:
    data: Dict[str, Any] = await ctx.http.get_json(
        SERPAPI,
        params={
            "q": search_query,
            "api_key": ctx.search_api_key,
            "num": ctx.max_results,
            "engine": "google",
        },
    )

    findings: List[Finding] = []
    for item in (data.get("organic_results") or [])[: ctx.max_results]:
        url = str(item.get("link") or "")
        if not url:
            continue
        findings.append(
            Finding(
                source=NAME,
                kind="profile" if username_from_profile_url(url) else "post",
                url=url,
                title=str(item.get("title") or ""),
                snippet=str(item.get("snippet") or ""),
                username=username_from_profile_url(url),
                extra={"engine": "serpapi", "query": search_query, "host": url_host(url)},
            )
        )
    return findings


async def _bing_api(search_query: str, ctx: SourceContext) -> List[Finding]:
    data: Dict[str, Any] = await ctx.http.get_json(
        BING_API,
        params={"q": search_query, "count": ctx.max_results, "mkt": "en-US"},
        headers={"Ocp-Apim-Subscription-Key": ctx.search_api_key},
    )

    findings: List[Finding] = []
    pages = ((data.get("webPages") or {}).get("value") or [])[: ctx.max_results]
    for item in pages:
        url = str(item.get("url") or "")
        if not url:
            continue
        findings.append(
            Finding(
                source=NAME,
                kind="profile" if username_from_profile_url(url) else "post",
                url=url,
                title=str(item.get("name") or ""),
                snippet=str(item.get("snippet") or ""),
                username=username_from_profile_url(url),
                extra={"engine": "bing", "query": search_query, "host": url_host(url)},
            )
        )
    return findings
