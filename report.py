"""
report.py — сборка текстового отчёта для Telegram.

Отчёт формируется в HTML (parse_mode=HTML) и режется на части по лимиту
длины сообщения. Структура:

  🔎 Запрос: <username> (<имя>)
  ✅ ТОЧНО — находки с высокой уверенностью
  🟡 ВЕРОЯТНО — сильные косвенные признаки
  ⚪️ НЕЯСНО — слабые упоминания
  🌐 Публичные профили — сводка ссылок
  📡 Источники — статус каждого (ок / пропущен / ошибка)

В отчёт попадают только публичные данные: username, публичное имя, ссылки,
публичные посты. Телефоны, адреса и e-mail из утечек не собираются и не выводятся.
"""

from __future__ import annotations

import html
from typing import Iterable, List

from orchestrator import SearchOutcome
from scorer import ScoredFinding, confidence_label, summarize_confidence

# Telegram ограничивает сообщение 4096 символами — берём с запасом.
MAX_MESSAGE_LEN = 3800
# Запас под префикс "(часть i/n)" при разбиении длинного отчёта.
PART_MARKER_RESERVE = 40
MAX_ITEMS_PER_BUCKET = 8
SNIPPET_LEN = 180

BUCKET_HEADERS = {
    "exact": "✅ <b>ТОЧНО</b> — совпадение подтверждается напрямую",
    "likely": "🟡 <b>ВЕРОЯТНО</b> — сильные косвенные признаки",
    "unclear": "⚪️ <b>НЕЯСНО</b> — слабое упоминание, возможен однофамилец",
}

SOURCE_LABELS = {
    "telegram_public": "Telegram (публичное превью)",
    "search_engines": "Поисковые системы",
    "github_public": "GitHub (публичный API)",
    "forums_public": "Форумы (Reddit / HN / StackOverflow)",
}


def esc(value: str) -> str:
    """Экранирование под Telegram HTML — иначе спецсимволы сломают разметку."""
    return html.escape(value or "", quote=False)


def _shorten(text: str, limit: int = SNIPPET_LEN) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _format_scored(scored: ScoredFinding, index: int) -> str:
    finding = scored.finding
    title = _shorten(finding.title or finding.display_name or finding.url, 110)
    lines = [f"{index}. <b>{esc(title)}</b>"]

    if finding.url:
        lines.append(f'   🔗 <a href="{esc(finding.url)}">{esc(_shorten(finding.url, 90))}</a>')

    if finding.display_name and finding.display_name.lower() not in title.lower():
        lines.append(f"   👤 {esc(_shorten(finding.display_name, 80))}")

    if finding.snippet:
        lines.append(f"   📝 {esc(_shorten(finding.snippet))}")

    extras: List[str] = []
    extra = finding.extra or {}
    if extra.get("stars"):
        extras.append(f"⭐ {extra['stars']}")
    if extra.get("language"):
        extras.append(str(extra["language"]))
    if extra.get("reputation"):
        extras.append(f"репутация {extra['reputation']}")
    if extra.get("subreddit"):
        extras.append(f"r/{extra['subreddit']}")
    if extras:
        lines.append("   📊 " + esc(", ".join(extras)))

    lines.append(
        f"   🎯 уверенность {scored.score:.2f} ({confidence_label(scored.bucket)}) — "
        f"{esc(scored.reasons[0] if scored.reasons else '')}"
    )
    return "\n".join(lines)


def _bucket_block(title: str, items: Iterable[ScoredFinding]) -> str:
    items = list(items)
    if not items:
        return ""
    block = [title, ""]
    for index, scored in enumerate(items[:MAX_ITEMS_PER_BUCKET], start=1):
        block.append(_format_scored(scored, index))
        block.append("")
    if len(items) > MAX_ITEMS_PER_BUCKET:
        block.append(f"…и ещё {len(items) - MAX_ITEMS_PER_BUCKET} находок в этой категории.")
        block.append("")
    return "\n".join(block)


def build_report(outcome: SearchOutcome) -> str:
    """Собирает полный текст отчёта (одна строка с \n, потом режется на части)."""
    query = outcome.query
    report = outcome.report

    header = [
        "🔎 <b>Отчёт по публичным данным</b>",
        "",
        f"👤 Запрос: <code>{esc(query.username or query.raw)}</code>"
        + (f" · имя: {esc(query.full_name)}" if query.full_name else ""),
        f"📈 Найдено: {report.total} — {esc(summarize_confidence(report))}",
        f"⏱ {outcome.duration:.1f} с" + (" · 🗄 из кэша" if outcome.cached else ""),
        "",
    ]

    body: List[str] = []
    for bucket in ("exact", "likely", "unclear"):
        block = _bucket_block(BUCKET_HEADERS[bucket], getattr(report, bucket))
        if block:
            body.append(block)

    if not body:
        body.append(
            "❌ Совпадений по публичным источникам не найдено.\n"
            "Возможные причины: username редкий/новый, источники недоступны (см. статус ниже).\n"
        )

    profiles = report.profile_links
    profile_block: List[str] = []
    if profiles:
        profile_block.append("🌐 <b>Публичные профили</b>")
        profile_block.append("")
        for platform, url in profiles[:12]:
            profile_block.append(f"• {esc(platform)} — {esc(url)}")
        profile_block.append("")

    sources_block = ["📡 <b>Статус источников</b>", ""]
    for source, status in outcome.source_status_lines():
        label = SOURCE_LABELS.get(source, source)
        icon = "✅" if status.startswith("ок") else ("⚠️" if status.startswith("пропущен") else "❌")
        sources_block.append(f"{icon} {esc(label)}: {esc(status)}")
    sources_block.append("")
    sources_block.append(
        "<i>Использованы только публичные страницы без авторизации. "
        "Телефоны, адреса и e-mail из утечек не собираются.</i>"
    )

    text = "\n".join(header + body + profile_block + sources_block)
    return text.strip()


def _safe_cut(text: str, limit: int) -> int:
    """
    Возвращает позицию разреза, не попадающую внутрь HTML-тега.
    Если в пределах limit открылся тег без закрывающей '>' — режем перед ним.
    """
    cut = limit
    last_open = text.rfind("<", 0, cut)
    if last_open != -1 and text.find(">", last_open, cut) == -1:
        cut = last_open
    return max(1, cut)


def split_message(text: str, limit: int = MAX_MESSAGE_LEN) -> List[str]:
    """Режет длинный отчёт на части, не разрывая HTML-теги посередине."""
    if len(text) <= limit:
        return [text]

    # Резервируем место под префикс "(часть i/n)", иначе части превысят лимит.
    budget = max(200, limit - PART_MARKER_RESERVE)
    parts: List[str] = []
    current: List[str] = []
    current_len = 0

    def flush() -> None:
        nonlocal current, current_len
        if current:
            parts.append("\n".join(current))
            current, current_len = [], 0

    for line in text.split("\n"):
        # Строка длиннее бюджета — режем её саму, не залезая внутрь тега.
        while len(line) > budget:
            flush()
            cut = _safe_cut(line, budget)
            parts.append(line[:cut])
            line = line[cut:]

        if current_len + len(line) + 1 > budget and current:
            flush()

        current.append(line)
        current_len += len(line) + 1

    flush()

    total = len(parts)
    if total <= 1:
        return parts

    prefix_len = len(f"<i>(часть {total}/{total})</i>\n")
    return [
        f"<i>(часть {i}/{total})</i>\n{p}"
        for i, p in enumerate(parts, start=1)
    ] if all(len(p) + prefix_len <= limit for p in parts) else parts


def build_help() -> str:
    return (
        "🛠 <b>OSINT-бот по публичным данным</b>\n\n"
        "<b>Поиск следа</b>\n"
        "• <code>/find &lt;username&gt; [имя]</code> — поиск по публичным источникам\n"
        "• просто отправьте <code>@username</code> или <code>username Имя Фамилия</code>\n\n"
        "<b>Доказательная папка (мошенничество)</b>\n"
        "• <code>/evidence &lt;домен | кошелёк | организация&gt;</code>\n"
        "  RDAP, DNS, поддомены, хостинг, блокчейн, реестры, санкции\n"
        "• <code>/evidence_json</code> — последний пакет в JSON для приложения к заявлению\n\n"
        "<b>Мониторинг публичных реестров</b>\n"
        "• <code>/watch &lt;название&gt;</code> — следить за изменениями\n"
        "• <code>/watch person:Иван Иванов</code> — явно указать тип\n"
        "• <code>/watches</code> — список наблюдений\n"
        "• <code>/unwatch &lt;название&gt;</code> — удалить наблюдение\n\n"
        "<b>Архив ваших чатов (Telegram Business)</b>\n"
        "• <code>/bizstatus</code> — как подключить и статус логирования\n"
        "• <code>/chats</code> — чаты в архиве, сколько сообщений и удалённых\n"
        "• <code>/deleted</code> — что собеседники удалили\n"
        "• <code>/archive</code> — полная выгрузка архива в JSON\n"
        "• <code>/digest_now</code> — недельная сводка прямо сейчас\n"
        "Работает только для чатов, которые вы сами открыли боту:\n"
        "Настройки → Telegram Business → Чат-боты.\n\n"
        "<b>Свой след</b>\n"
        "• <code>/mytrace &lt;username&gt;</code> — что о вас видно публично\n"
        "• <code>/mytrace --pw &lt;пароль&gt;</code> — проверка пароля в утечках\n"
        "• <code>/breaches [слово]</code> — каталог крупных утечек\n\n"
        "<b>Прочее</b>\n"
        "• <code>/limits</code> — остаток дневного лимита и статус кэша\n"
        "• <code>/history</code> — последние запросы\n"
        "• <code>/delete_me</code> — удалить всю свою историю, наблюдения, архив чатов и счётчики\n"
        "• <code>/setkey</code> — сменить поисковый провайдер/ключ на ходу\n"
        "• <code>/help</code> — эта справка\n\n"
        "Что собирается: username, публичное имя, ссылки на публичные профили, "
        "публичные посты, официальные реестры, публичные данные блокчейна, "
        "а также архив ваших собственных чатов (если подключили Business).\n"
        "Что НЕ собирается: телефоны, адреса, e-mail из утечек, паспортные данные, "
        "закрытые профили, переписка чатов, которые вы не открывали боту. "
        "Пароль проверяется через k-anonymity и не покидает сервер.\n"
        "Работают только публичные страницы без авторизации и обхода капчи."
    )
