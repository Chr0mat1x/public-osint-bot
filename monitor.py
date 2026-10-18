"""
monitor.py — Public Accountability Tracker: мониторинг публичной деятельности.

Пользователь ставит «наблюдение» за организацией или публичной фигурой, и бот
периодически перечитывает официальные реестры. Когда появляется новая запись —
присылает уведомление с тем, что именно изменилось.

Источники — только официальные реестры (GLEIF, SEC EDGAR, OFAC SDN, Wikidata).
Никаких слитых баз, никакого сбора персональных данных.

Как работает сравнение: из находок собирается «отпечаток» — отсортированный
набор ключей (реестр + идентификатор). Если отпечаток изменился, считаем
разницу по множествам и показываем только новые и исчезнувшие записи.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from normalizer import Finding

from sources import registries_public
from sources.http_client import HttpClient, HttpError

log = logging.getLogger("osint-bot")

KIND_COMPANY = "company"
KIND_PERSON = "person"

# Пауза между обходами наблюдений в фоне.
DEFAULT_INTERVAL_SECONDS = 6 * 3600

# Сколько снимков истории держим на одно наблюдение.
SNAPSHOT_KEEP = 10


def detect_kind(subject: str) -> str:
    """
    Определяет тип субъекта по вводу.

    Явный префикс важнее эвристики: пользователь может точно указать,
    компания это или человек.
    """
    lowered = subject.strip().lower()
    if lowered.startswith("company:"):
        return KIND_COMPANY
    if lowered.startswith("person:"):
        return KIND_PERSON

    # Эвристика: организационные маркеры в названии.
    org_markers = (
        "llc", "ltd", "inc", "corp", "gmbh", "ооо", "оао", "зао", "пао",
        "company", "group", "bank", "fund", "labs", "studio", "holdings",
    )
    words = set(lowered.replace(",", " ").replace(".", " ").split())
    if words & set(org_markers):
        return KIND_COMPANY
    return KIND_PERSON


def clean_subject(subject: str) -> str:
    """Убирает служебный префикс перед сохранением и показом."""
    for prefix in ("company:", "person:"):
        if subject.strip().lower().startswith(prefix):
            return subject.strip()[len(prefix):].strip()
    return subject.strip()


def _finding_key(finding: Finding) -> str:
    """
    Стабильный ключ записи для сравнения снимков.

    Берём реестр и главный идентификатор, а не URL целиком: URL может
    измениться (редирект, смена ссылки), а запись остаться той же.
    """
    extra = finding.extra or {}
    registry = str(extra.get("registry") or finding.source)
    identifier = (
        extra.get("lei")
        or extra.get("qid")
        or extra.get("cik")
        or extra.get("programs")
        or finding.url
    )
    return f"{registry}|{identifier}"


def _fingerprint(findings: List[Finding]) -> str:
    """SHA-256 по отсортированному набору ключей — компактный «отпечаток»."""
    keys = sorted(_finding_key(f) for f in findings)
    digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()
    return digest


def _payload(findings: List[Finding]) -> Dict[str, Any]:
    """Полезная нагрузка снимка: ключи для сравнения + данные для показа."""
    return {
        "items": [
            {
                "key": _finding_key(f),
                "title": f.title,
                "url": f.url,
                "snippet": f.snippet,
                "registry": (f.extra or {}).get("registry", f.source),
            }
            for f in findings
        ]
    }


@dataclass
class WatchCheck:
    """Результат одной проверки наблюдения."""

    subject: str
    kind: str
    findings: List[Finding] = field(default_factory=list)
    added: List[Dict[str, Any]] = field(default_factory=list)
    removed: List[Dict[str, Any]] = field(default_factory=list)
    first_run: bool = False
    error: Optional[str] = None

    @property
    def changed(self) -> bool:
        return bool(self.added or self.removed)


async def collect_subject(http: HttpClient, subject: str, kind: str) -> List[Finding]:
    """Опрашивает официальные реестры по субъекту."""
    findings: List[Finding] = []

    if kind == KIND_COMPANY:
        for step in (
            registries_public.gleif_search,
            registries_public.ofac_sanctions,
            registries_public.sec_filings,
        ):
            try:
                findings.extend(await step(http, subject))
            except HttpError as exc:
                log.debug("Мониторинг: источник %s не ответил: %s", step.__name__, exc)
    else:
        try:
            findings.extend(await registries_public.wikidata_person(http, subject))
        except HttpError as exc:
            log.debug("Мониторинг: Wikidata не ответил: %s", exc)
        try:
            findings.extend(await registries_public.ofac_sanctions(http, subject))
        except HttpError as exc:
            log.debug("Мониторинг: OFAC не ответил: %s", exc)

    return findings


def diff_snapshots(
    previous: Optional[Dict[str, Any]], current: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Считает разницу между снимками по ключам записей.

    Возвращает (добавленные, исчезнувшие). Если предыдущего снимка нет,
    всё считается добавленным — это первый прогон.
    """
    current_items = {item["key"]: item for item in current.get("items", [])}
    previous_items = {item["key"]: item for item in (previous or {}).get("items", [])}

    added = [item for key, item in current_items.items() if key not in previous_items]
    removed = [item for key, item in previous_items.items() if key not in current_items]
    return added, removed


async def check_watch(storage, watch_row, http: HttpClient) -> WatchCheck:
    """
    Проверяет одно наблюдение и сохраняет снимок.

    Возвращает разницу. Ошибка сети не стирает историю: снимок не пишется,
    наблюдение остаётся с прежним состоянием и будет проверено позже.
    """
    subject = watch_row["subject"]
    kind = watch_row["kind"]
    watch_id = watch_row["id"]

    check = WatchCheck(subject=subject, kind=kind)

    try:
        findings = await collect_subject(http, subject, kind)
    except Exception as exc:  # сеть/парсинг: не роняем фоновый обход
        check.error = str(exc)
        return check

    check.findings = findings
    current = _payload(findings)
    current_fp = _fingerprint(findings)

    last = storage.snapshot_last(watch_id)
    previous_payload = json.loads(last["payload"]) if last else None
    previous_fp = last["fingerprint"] if last else None

    if previous_fp is None:
        check.first_run = True
    elif previous_fp != current_fp:
        added, removed = diff_snapshots(previous_payload, current)
        check.added = added
        check.removed = removed

    # Снимок пишем, только если он отличается — иначе БД растёт впустую.
    if previous_fp != current_fp:
        storage.snapshot_add(watch_id, current_fp, current)
        storage.snapshot_prune(watch_id, keep=SNAPSHOT_KEEP)

    storage.watch_touch(watch_id)
    return check


def _esc(value: str) -> str:
    return str(value or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _short(value: str, limit: int = 160) -> str:
    value = " ".join(str(value or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def build_watch_report(check: WatchCheck) -> str:
    """Формирует уведомление об изменениях по наблюдению."""
    lines = [f"🔔 <b>Изменения по «{_esc(check.subject)}»</b>", ""]

    if check.error:
        lines.append(f"⚠️ Не удалось проверить: {_esc(_short(check.error, 160))}")
        return "\n".join(lines)

    if check.first_run:
        lines.append(f"👀 Наблюдение создано. Найдено записей: {len(check.findings)}.")
        lines.append("")
        lines.append("Дальше бот будет присылать только изменения.")
        return "\n".join(lines)

    if not check.changed:
        lines.append("Без изменений с прошлой проверки.")
        return "\n".join(lines)

    if check.added:
        lines.append(f"➕ <b>Новые записи: {len(check.added)}</b>")
        lines.append("")
        for item in check.added[:15]:
            lines.append(f"• [{_esc(item.get('registry', ''))}] {_esc(_short(item.get('title', '')))}")
            if item.get("url"):
                lines.append(f'   <a href="{_esc(item["url"])}">{_esc(_short(item["url"], 80))}</a>')
        lines.append("")

    if check.removed:
        lines.append(f"➖ <b>Исчезли из реестров: {len(check.removed)}</b>")
        lines.append("")
        for item in check.removed[:15]:
            lines.append(f"• [{_esc(item.get('registry', ''))}] {_esc(_short(item.get('title', '')))}")
        lines.append("")

    lines.append("<i>Источники: официальные реестры (GLEIF, SEC EDGAR, OFAC SDN, Wikidata).</i>")
    return "\n".join(lines)


def build_watch_list(rows: List[Any]) -> str:
    """Список наблюдений пользователя."""
    if not rows:
        return (
            "📭 Наблюдений пока нет.\n\n"
            "Добавить: <code>/watch ООО Ромашка</code>\n"
            "Или явно указать тип: <code>/watch person:Иван Иванов</code>"
        )

    lines = ["👀 <b>Мои наблюдения</b>", ""]
    for row in rows:
        kind_label = "организация" if row["kind"] == KIND_COMPANY else "человек"
        last = row["last_check"]
        when = (
            time.strftime("%Y-%m-%d %H:%M", time.gmtime(last)) + " UTC" if last else "ещё не проверялось"
        )
        lines.append(f"• <b>{_esc(row['subject'])}</b> ({kind_label}) — {_esc(when)}")
    lines.append("")
    lines.append("Удалить: <code>/unwatch название</code>")
    return "\n".join(lines)


async def monitor_loop(storage, http: HttpClient, bot, interval: int = DEFAULT_INTERVAL_SECONDS) -> None:
    """
    Фоновый обход всех наблюдений.

    Запускается как отдельная задача при старте бота. Каждый цикл проверяет
    все наблюдения и отправляет уведомление владельцу при изменениях.
    """
    log.info("Мониторинг запущен, интервал %d с", interval)
    while True:
        try:
            await asyncio.sleep(interval)
            rows = storage.watch_all()
            if not rows:
                continue

            log.info("Мониторинг: проверяю наблюдений — %d", len(rows))
            for row in rows:
                try:
                    check = await check_watch(storage, row, http)
                    if check.changed and not check.first_run:
                        await bot.send_message(row["user_id"], build_watch_report(check))
                        log.info("Мониторинг: уведомление отправлено (%s)", row["subject"])
                except Exception as exc:
                    log.warning("Мониторинг: ошибка по «%s»: %s", row["subject"], exc)
        except asyncio.CancelledError:
            log.info("Мониторинг остановлен.")
            raise
        except Exception as exc:
            log.error("Мониторинг: сбой цикла: %s", exc)
