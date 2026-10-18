"""
normalizer.py — модели данных и нормализация результатов источников.

Задача модуля: привести «сырые» находки из разных источников к единому виду,
чтобы их можно было дедуплицировать, сравнивать и оценивать.

Здесь же — функции нормализации username и URL. Никакие персональные данные
(телефоны, адреса, e-mail из утечек) модель Finding не содержит по определению.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Допустимые символы username в популярных сервисах.
USERNAME_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9._-]{1,38})$")

# Параметры URL, которые не влияют на содержимое страницы — выкидываем при канонизации.
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "yclid", "ref", "ref_src", "igshid", "si", "spm",
}

# Известные шаблоны «профильных» URL: домен → позиция username в пути.
PROFILE_URL_PATTERNS = (
    (re.compile(r"^github\.com$"), 0),
    (re.compile(r"^(?:www\.)?reddit\.com$"), 1),   # /user/<name> или /u/<name>
    (re.compile(r"^(?:www\.)?t\.me$"), 0),
    (re.compile(r"^(?:www\.)?last\.fm$"), 1),     # /user/<name>
    (re.compile(r"^(?:www\.)?soundcloud\.com$"), 0),
    (re.compile(r"^(?:www\.)?medium\.com$"), 0),  # /@name
    (re.compile(r"^(?:www\.)?twitch\.tv$"), 0),
    (re.compile(r"^(?:www\.)?pinterest\.[a-z.]+$"), 0),
    (re.compile(r"^(?:www\.)?habr\.com$"), 1),    # /users/<name>
)

# Служебные сегменты пути, которые не могут быть username.
RESERVED_SEGMENTS = {
    "user", "users", "u", "profile", "profiles", "people", "member", "members",
    "search", "settings", "login", "signup", "about", "help", "explore",
    "topics", "orgs", "sponsors", "features", "collections", "trending",
}


# --------------------------------------------------------------------------- #
# Модели
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """Одна публичная находка. Персональные контакты сюда не попадают."""

    source: str                 # имя источника: telegram_public / search / github / forums
    kind: str                   # profile | post | repo | forum_post
    url: str
    title: str = ""
    snippet: str = ""
    username: str = ""          # username, извлечённый со страницы/URL
    display_name: str = ""      # публичное отображаемое имя
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SourceResult:
    """Результат опроса одного источника: данные + статус для отчёта."""

    source: str
    ok: bool = True
    skipped: bool = False
    error: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)

    @classmethod
    def failure(cls, source: str, error: str) -> "SourceResult":
        return cls(source=source, ok=False, error=error)

    @classmethod
    def skip(cls, source: str, reason: str) -> "SourceResult":
        return cls(source=source, ok=True, skipped=True, error=reason)


@dataclass
class Query:
    """Нормализованный запрос пользователя."""

    raw: str
    username: str
    full_name: str = ""

    def cache_key(self) -> str:
        return f"{self.username}|{self.full_name}".lower()


# --------------------------------------------------------------------------- #
# Нормализация username / URL
# --------------------------------------------------------------------------- #
def normalize_username(raw: str) -> str:
    """
    Приводит ввод к каноничному виду: убирает @, ссылки t.me/, пробелы,
    приводит к нижнему регистру. Возвращает "" если username некорректен.
    """
    if not raw:
        return ""

    value = raw.strip()

    # Если вставили ссылку — вытаскиваем последний сегмент пути.
    if "://" in value or value.startswith("t.me/"):
        url = value if "://" in value else f"https://{value}"
        username_from_url = username_from_profile_url(url)
        if username_from_url:
            return username_from_url

    value = value.lstrip("@").strip()

    if USERNAME_RE.match(value):
        return value.lower()
    return ""


def canonical_url(url: str) -> str:
    """Убирает трекинг-параметры и фрагмент, приводит схему/хост к нижнему регистру."""
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return url.strip()

    if not parts.netloc:
        return url.strip()

    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k.lower() not in TRACKING_PARAMS]

    return urlunsplit((
        (parts.scheme or "https").lower(),
        parts.netloc.lower(),
        parts.path.rstrip("/") or "/",
        urlencode(query),
        "",  # фрагмент не нужен: якоря не создают новых сущностей
    ))


def url_host(url: str) -> str:
    try:
        return urlsplit(url).netloc.lower()
    except ValueError:
        return ""


def username_from_profile_url(url: str) -> str:
    """Извлекает username из URL известных сервисов. "" если не распознали."""
    try:
        parts = urlsplit(url if "://" in url else f"https://{url}")
    except ValueError:
        return ""

    host = parts.netloc.lower()
    segments = [s for s in parts.path.split("/") if s]

    for pattern, index in PROFILE_URL_PATTERNS:
        if pattern.match(host) and len(segments) > index:
            candidate = segments[index].lstrip("@")
            if candidate.lower() in RESERVED_SEGMENTS:
                return ""
            return candidate.lower() if USERNAME_RE.match(candidate) else ""
    return ""


def looks_like_username_match(finding: Finding, username: str) -> bool:
    """
    Грубая проверка «эта находка вообще про нашего пользователя?».
    Сравниваем username из URL, заголовка и сниппета.
    """
    target = username.lower()
    haystacks = [
        finding.username.lower(),
        finding.display_name.lower(),
        finding.title.lower(),
        finding.snippet.lower(),
        finding.url.lower(),
    ]
    for text in haystacks:
        if not text:
            continue
        # Точное совпадение как отдельного токена, чтобы "ann" не ловил "annabelle".
        if re.search(rf"(?<![a-z0-9._-]){re.escape(target)}(?![a-z0-9._-])", text):
            return True
    return False


# --------------------------------------------------------------------------- #
# Дедупликация и слияние
# --------------------------------------------------------------------------- #
def deduplicate(findings: Iterable[Finding]) -> List[Finding]:
    """
    Убирает дубли по каноническому URL. Если один и тот же URL пришёл из
    нескольких источников — склеиваем сниппеты и помечаем все источники.
    """
    merged: Dict[str, Finding] = {}

    for finding in findings:
        if not finding.url:
            continue
        key = canonical_url(finding.url)
        existing = merged.get(key)
        if existing is None:
            finding.url = key
            merged[key] = finding
            continue

        # Дополняем уже известную находку новыми деталями.
        if finding.snippet and finding.snippet not in existing.snippet:
            existing.snippet = (existing.snippet + " | " + finding.snippet).strip(" |")[:500]
        if finding.display_name and not existing.display_name:
            existing.display_name = finding.display_name
        if finding.username and not existing.username:
            existing.username = finding.username

        sources = set(str(existing.extra.get("sources", existing.source)).split(","))
        sources.add(finding.source)
        existing.extra["sources"] = ",".join(sorted(s.strip() for s in sources if s.strip()))

    return list(merged.values())


def filter_by_query(findings: Iterable[Finding], query: "Query") -> List[Finding]:
    """
    Отсеивает явный шум: оставляем находки, где встречается username
    ИЛИ полное имя целиком. Скоринг потом расставит их по корзинам.

    Если username не распознан (поиск только по имени) — ничего не отсеиваем,
    иначе можно потерять все результаты.
    """
    findings = list(findings)
    if not query.username:
        return findings

    target_user = query.username.lower()
    target_name = (query.full_name or "").lower()

    kept: List[Finding] = []
    for finding in findings:
        if looks_like_username_match(finding, target_user):
            kept.append(finding)
            continue
        if target_name and target_name in " ".join(
            [finding.display_name.lower(), finding.title.lower(), finding.snippet.lower()]
        ):
            kept.append(finding)
    return kept


def build_query(raw: str) -> Query:
    """
    Разбирает пользовательский ввод вида "ivan_petrov Иван Петров" или "@ivan_petrov".
    Username — первый валидный токен, остальное — предполагаемое публичное имя.
    """
    raw = (raw or "").strip()
    tokens = raw.split()

    username = ""
    rest: List[str] = []
    for token in tokens:
        if not username:
            candidate = normalize_username(token)
            if candidate:
                username = candidate
                continue
        rest.append(token)

    full_name = " ".join(rest).strip()
    if not username and full_name:
        # Username не нашли — попробуем собрать из имени (латиница без пробелов).
        username = normalize_username(re.sub(r"[^0-9a-zA-Z._-]", "", full_name.replace(" ", "_")))

    return Query(raw=raw, username=username, full_name=full_name)
