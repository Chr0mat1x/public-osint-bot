"""
selftrace.py — Self-Trace Auditor: аудит собственного публичного следа.

Режим работает по данным, которые пользователь подтвердил как свои. Бот
показывает, что о нём видно в публичных источниках, и даёт конкретные шаги
по сокращению следа.

Три проверки:
  1. Публичный след — что находится по вашему username (обычные источники);
  2. Пароль — встречался ли он в публичных утечках (HIBP k-anonymity,
     без передачи пароля и полного хеша наружу);
  3. Каталог утечек — какие сервисы утекали, что именно и когда.

Отличие от обычного поиска: здесь нет попытки связать человека с посторонними
аккаунтами. Отчёт намеренно строится как «что видно снаружи» + «что с этим
сделать».
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

from normalizer import Finding

from sources import breach_public
from sources.http_client import HttpClient, HttpError

MAX_CATALOG_ITEMS = 10


@dataclass
class SelfTraceResult:
    """Итог самопроверки."""

    username: str = ""
    footprint: List[Finding] = field(default_factory=list)
    password_checked: bool = False
    password_occurrences: int = 0
    password_error: Optional[str] = None
    breaches: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


async def check_password(http: HttpClient, password: str, result: SelfTraceResult) -> None:
    """
    Проверяет пароль через k-anonymity.

    Пароль не покидает процесс: наружу уходит только первые 5 символов
    SHA-1 хеша. По ним восстановить пароль невозможно.
    """
    try:
        finding = await breach_public.password_exposure(http, password)
        result.password_checked = True
        result.password_occurrences = int(finding.extra.get("occurrences") or 0)
    except HttpError as exc:
        result.password_error = str(exc)


async def load_catalog(http: HttpClient, result: SelfTraceResult, keyword: str = "") -> None:
    """Загружает публичный каталог утечек."""
    try:
        result.breaches = await breach_public.breach_catalog(http, keyword=keyword)
    except HttpError as exc:
        result.notes.append(f"Каталог утечек: {exc}")


def _esc(value: str) -> str:
    return str(value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _short(value: str, limit: int = 200) -> str:
    value = " ".join(str(value or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def build_selftrace_report(result: SelfTraceResult) -> str:
    """Собирает отчёт самопроверки с конкретными шагами по каждому пункту."""
    lines = ["🔐 <b>Аудит вашего публичного следа</b>", ""]

    if result.username:
        lines.append(f"👤 Проверяемый username: <code>{_esc(result.username)}</code>")
    lines.append("")

    # 1. Публичный след.
    lines.append("🌐 <b>Что видно в публичных источниках</b>")
    lines.append("")
    if result.footprint:
        for finding in result.footprint[:12]:
            lines.append(f"• {_esc(finding.title or finding.url)}")
            lines.append(f'   <a href="{_esc(finding.url)}">{_esc(_short(finding.url, 80))}</a>')
        if len(result.footprint) > 12:
            lines.append(f"…и ещё {len(result.footprint) - 12} записей.")
    else:
        lines.append("Ничего не найдено — след по этому username минимален.")
    lines.append("")

    # 2. Пароль.
    lines.append("🔑 <b>Проверка пароля</b>")
    lines.append("")
    if result.password_error:
        lines.append(f"⚠️ Не удалось проверить: {_esc(_short(result.password_error, 140))}")
    elif not result.password_checked:
        lines.append("Проверка не выполнялась.")
    elif result.password_occurrences:
        lines.append(
            f"🚨 Пароль найден в публичных утечках <b>{result.password_occurrences}</b> раз."
        )
        lines.append("")
        lines.append("Что делать: смените его на всех сервисах, где он использовался,")
        lines.append("и включите двухфакторную аутентификацию. Такой пароль подбирают автоматически.")
    else:
        lines.append("✅ Пароль в известных публичных утечках не встречается.")
    lines.append("")
    lines.append("<i>Пароль не передавался: отправлены только 5 символов SHA-1 хеша (k-anonymity).</i>")
    lines.append("")

    # 3. Каталог утечек.
    if result.breaches:
        lines.append("🗂 <b>Крупные публичные утечки</b>")
        lines.append("")
        for breach in result.breaches[:MAX_CATALOG_ITEMS]:
            lines.append(f"• {_esc(breach.title)} — {_esc(_short(breach.snippet, 120))}")
        lines.append("")

    if result.notes:
        lines.append("⚠️ <b>Замечания</b>")
        lines.append("")
        for note in result.notes[:6]:
            lines.append(f"• {_esc(_short(note, 140))}")
        lines.append("")

    lines.extend(
        [
            "📌 <b>Как сократить след</b>",
            "",
            "1. Смените пароли, которые всплыли в утечках, и не повторяйте их.",
            "2. Включите 2FA везде, где это возможно.",
            "3. Удалите старые аккаунты, которыми не пользуетесь.",
            "4. Проверьте настройки приватности в соцсетях.",
            "5. Для удаления данных из поиска используйте официальные формы сервисов.",
        ]
    )

    return "\n".join(lines).strip()


async def run_selftrace(
    http: HttpClient,
    username: str,
    password: str = "",
    footprint_collector=None,
) -> SelfTraceResult:
    """
    Выполняет самопроверку.

    footprint_collector — функция поиска публичного следа; передаётся из bot.py,
    чтобы не дублировать логику обычного поиска.
    """
    result = SelfTraceResult(username=username)

    tasks = []
    if password:
        tasks.append(check_password(http, password, result))
    tasks.append(load_catalog(http, result))

    if footprint_collector is not None and username:
        try:
            result.footprint = await footprint_collector(username)
        except Exception as exc:
            result.notes.append(f"Поиск публичного следа: {exc}")

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    return result
