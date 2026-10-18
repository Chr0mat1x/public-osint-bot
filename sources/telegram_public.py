"""
sources/telegram_public.py — публичный веб-превью Telegram (t.me).

Что делаем:
  * проверяем существование публичного username через https://t.me/<username>
    (это обычная HTML-страница превью, доступная без входа в аккаунт);
  * извлекаем публичное отображаемое имя, описание и аватар из Open Graph-тегов;
  * для каналов дополнительно тянем публичную страницу /s/<username> (веб-превью постов).

Чего НЕ делаем:
  * не используем Telegram API с user-сессией (это уже авторизация);
  * не парсим закрытые/приватные профили;
  * не собираем телефоны и любые контакты.
"""

from __future__ import annotations

import html
import re
from typing import Dict, List

from normalizer import Finding, Query, SourceResult

from .http_client import HttpError, HttpClient
from . import SourceContext

NAME = "telegram_public"
BASE = "https://t.me"

# Telegram отдаёт превью-страницу с Open Graph-тегами.
OG_RE = re.compile(
    r'<meta\s+property="og:(?P<prop>title|description|image)"\s+content="(?P<value>[^"]*)"',
    re.IGNORECASE,
)
TITLE_RE = re.compile(r"<title>(?P<value>[^<]*)</title>", re.IGNORECASE)
# Каждое сообщение в веб-превью канала — блок с атрибутом data-post="<channel>/<id>".
MESSAGE_BLOCK_RE = re.compile(
    r'<div class="tgme_widget_message[^"]*"[^>]*data-post="(?P<post>[^"]+)"(?P<body>.*?)'
    r'(?=<div class="tgme_widget_message[^"]*"[^>]*data-post="|</main>|$)',
    re.DOTALL,
)
POST_TEXT_RE = re.compile(
    r'<div class="tgme_widget_message_text[^"]*"[^>]*>(?P<text>.*?)</div>', re.IGNORECASE | re.DOTALL
)
TAGS_RE = re.compile(r"<[^>]+>")

# Признаки страницы-заглушки: Telegram отдаёт её для несуществующего username.
NOT_FOUND_MARKERS = ("tgme_page_icon",)


def _strip_html(value: str) -> str:
    """Убирает теги и раскрывает HTML-сущности, сжимает пробелы."""
    text = TAGS_RE.sub(" ", value or "")
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _extract_meta(page: str) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for match in OG_RE.finditer(page):
        meta.setdefault(match.group("prop").lower(), html.unescape(match.group("value")))

    if "title" not in meta:
        title = TITLE_RE.search(page)
        if title:
            meta["title"] = html.unescape(title.group("value"))
    return meta


def _profile_exists(page: str, meta: Dict[str, str], username: str) -> bool:
    """
    Определяет, есть ли публичный профиль.

    Telegram для несуществующего username отдаёт заглушку, у которой:
      * нет блока с аватаром (tgme_page_photo), но есть tgme_page_icon;
      * og:title равен "Telegram: Contact @<username>" и og:description пуст.

    Для реального профиля/канала og:title — это публичное имя владельца.
    """
    title = (meta.get("title") or "").strip()
    placeholder_title = title.lower() == f"telegram: contact @{username}".lower()
    has_photo = "tgme_page_photo" in page

    if placeholder_title and not has_photo:
        return False
    if not title or title.lower().startswith("telegram: contact @"):
        return False
    return True


async def collect(query: Query, ctx: SourceContext) -> SourceResult:
    if not query.username:
        return SourceResult.skip(NAME, "username не распознан — Telegram-источник пропущен.")

    http: HttpClient = ctx.http
    findings: List[Finding] = []

    try:
        page = await http.get_text(f"{BASE}/{query.username}")
    except HttpError as exc:
        return SourceResult.failure(NAME, str(exc))

    meta = _extract_meta(page)
    title = _strip_html(meta.get("title", ""))
    description = _strip_html(meta.get("description", ""))
    avatar = meta.get("image", "")

    # Telegram для несуществующего username отдаёт страницу-заглушку —
    # её нельзя показывать как находку, иначе получим ложное «точно».
    if not _profile_exists(page, meta, query.username):
        return SourceResult(
            source=NAME,
            ok=True,
            findings=[],
            error="Публичный профиль/канал с таким username не найден.",
        )

    # Публичное отображаемое имя: у Telegram в title обычно "<Имя>" или "<Имя> – <описание>".
    display_name = title.split("–")[0].split("—")[0].strip() or title

    findings.append(
        Finding(
            source=NAME,
            kind="profile",
            url=f"{BASE}/{query.username}",
            title=title or f"@{query.username}",
            snippet=description,
            username=query.username,
            display_name=display_name,
            extra={"avatar": avatar} if avatar else {},
        )
    )

    # Пробуем получить публичные посты канала (веб-превью, без авторизации).
    try:
        posts_page = await http.get_text(f"{BASE}/s/{query.username}")
        findings.extend(_parse_posts(posts_page, query.username, ctx.max_results))
    except HttpError:
        # Посты недоступны (например, это личный аккаунт, а не канал) — не ошибка.
        pass

    return SourceResult(source=NAME, ok=True, findings=findings[: ctx.max_results])


def _parse_posts(page: str, username: str, limit: int) -> List[Finding]:
    """
    Вытаскивает публичные посты из HTML веб-превью канала.

    У каждого поста есть data-post="<channel>/<id>" — из него собирается
    точная публичная ссылка вида https://t.me/<channel>/<id>.
    """
    posts: List[Finding] = []
    seen_posts: set[str] = set()

    for match in MESSAGE_BLOCK_RE.finditer(page):
        post_id = (match.group("post") or "").strip()
        if not post_id or post_id in seen_posts:
            continue

        text_match = POST_TEXT_RE.search(match.group("body") or "")
        if not text_match:
            # Пост без текста (только медиа/служебное сообщение) — пропускаем.
            continue

        text = _strip_html(text_match.group("text"))
        if not text:
            continue

        seen_posts.add(post_id)
        posts.append(
            Finding(
                source=NAME,
                kind="post",
                url=f"{BASE}/{post_id}",
                title=text[:80],
                snippet=text[:400],
                username=username,
            )
        )
        if len(posts) >= limit:
            break

    return posts
