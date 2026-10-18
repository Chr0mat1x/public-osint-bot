"""
bizlog.py — логирование личных чатов через Telegram Business.

Как это работает по замыслу Telegram: владелец аккаунта сам подключает бота
(Настройки → Telegram Business → Чат-боты) и сам выбирает, какие чаты ему
открыть. Дальше бот получает апдейты по этим чатам:

  business_connection         — подключение создано / изменено / отключено
  business_message            — новое сообщение в открытом чате
  edited_business_message     — сообщение изменено
  deleted_business_messages   — сообщение удалено (содержимого в апдейте нет)

Ключевой момент про удаления: Telegram присылает только идентификаторы
удалённых сообщений, без текста. Поэтому «что удалили» берётся из архива,
который бот записал заранее. Нет записи в архиве — нечего и показывать.

Изоляция: данные каждого подключения привязаны к connection_id, а уведомления
и сводки уходят только владельцу этого подключения (owner_user_id). Собирать
переписку одного пользователя и отдавать её другому этот модуль не умеет.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import report as report_module

log = logging.getLogger("osint-bot")

# Как часто просыпается фоновая задача (проверка расписания сводок + очистка).
LOOP_TICK_SECONDS = 600

# Ключ в settings, где храним время последней отправленной сводки.
_DIGEST_SENT_KEY = "biz_digest_sent:{conn}"
_PRUNE_KEY = "biz_last_prune"

# Плейсхолдеры для не-текстовых сообщений: в архив попадает пометка, а не
# содержимое файла. Сами медиа не скачиваем — незачем хранить чужие файлы.
_MEDIA_LABELS = {
    "photo": "[фото]",
    "video": "[видео]",
    "animation": "[гиф]",
    "video_note": "[видеосообщение]",
    "voice": "[голосовое]",
    "audio": "[аудио]",
    "document": "[файл]",
    "sticker": "[стикер]",
    "location": "[геолокация]",
    "venue": "[место]",
    "contact": "[контакт]",
    "poll": "[опрос]",
    "dice": "[кубик]",
    "game": "[игра]",
}


def _esc(value: str) -> str:
    return html.escape(value or "", quote=False)


def _epoch(value: Any, default: Optional[float] = None) -> float:
    """
    Приводит время к epoch-секундам.

    aiogram отдаёт даты как datetime, Telegram в JSON — как unix-время.
    Поддерживаем оба варианта, чтобы не зависеть от версии.
    """
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    return default if default is not None else time.time()


def _ts(value: float) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def chat_title(chat: Any) -> str:
    """Человекочитаемое имя чата: заголовок группы или имя собеседника."""
    title = getattr(chat, "title", None)
    if title:
        return title
    parts = [getattr(chat, "first_name", None), getattr(chat, "last_name", None)]
    name = " ".join(p for p in parts if p)
    if name:
        return name
    username = getattr(chat, "username", None)
    return f"@{username}" if username else str(getattr(chat, "id", ""))


def chat_type_of(chat: Any) -> str:
    return str(getattr(chat, "type", "") or "")


def extract_content(message: Any) -> Tuple[str, str]:
    """
    Возвращает (content_type, текст) для архива.

    Для текста — сам текст, для подписи к медиа — подпись, для остального —
    пометка вида «[фото]». Содержимое файлов не сохраняем.
    """
    content_type = str(getattr(message, "content_type", "") or "unknown")

    text = getattr(message, "text", None)
    if text:
        return "text", text

    caption = getattr(message, "caption", None)
    if caption:
        return content_type, caption

    label = _MEDIA_LABELS.get(content_type)
    if label is None and content_type in ("service", "new_chat_members", "left_chat_member"):
        label = "[служебное сообщение]"
    return content_type, label or f"[{content_type}]"


def sender_name_of(user: Any) -> str:
    if user is None:
        return ""
    parts = [getattr(user, "first_name", None), getattr(user, "last_name", None)]
    name = " ".join(p for p in parts if p)
    if name:
        return name
    username = getattr(user, "username", None)
    return f"@{username}" if username else ""


# --------------------------------------------------------------------------- #
# Обработка апдейтов
# --------------------------------------------------------------------------- #
def register_connection(storage: Any, connection: Any) -> int:
    """
    Сохраняет подключение и возвращает owner_user_id.

    is_enabled отражает, активно ли подключение: при отключении Telegram
    присылает тот же апдейт с is_enabled=False.
    """
    owner_id = int(connection.user.id)
    state, _ = rights_summary(connection)
    storage.biz_connection_upsert(
        connection_id=str(connection.id),
        owner_user_id=owner_id,
        user_chat_id=int(connection.user_chat_id) if connection.user_chat_id else None,
        is_enabled=bool(connection.is_enabled),
        rights=state,
    )
    return owner_id


def rights_summary(connection: Any) -> tuple[str, list[str]]:
    """
    Возвращает (состояние, список предупреждений) по правам подключения.

    Для архива обязательно только право читать сообщения: без него Telegram
    не пришлёт business_message и архив останется пустым. Права отвечать и
    удалять нужны лишь для действий от имени владельца.
    """
    rights = getattr(connection, "rights", None)
    if rights is None:
        return "не переданы Telegram", ["Права ещё не пришли: переподключите бота в настройках."]

    can_read = getattr(rights, "can_read_messages", None)
    can_delete = getattr(rights, "can_delete_all_messages", None) or getattr(
        rights, "can_delete_sent_messages", None
    )
    can_reply = getattr(rights, "can_reply", None)

    warnings: list[str] = []
    if not can_read:
        warnings.append(
            "Нет права «читать сообщения» — это обязательное право, без него архив будет пустым."
        )

    granted = [
        label
        for label, value in (
            ("чтение", can_read),
            ("ответы", can_reply),
            ("удаление", can_delete),
        )
        if value
    ]
    state = ", ".join(granted) if granted else "ни одного права"
    return state, warnings


def store_message(storage: Any, connection_id: str, message: Any, owner_user_id: int) -> None:
    """Кладёт сообщение в архив. Тихо игнорирует то, что не является сообщением."""
    chat = getattr(message, "chat", None)
    if chat is None or message.message_id is None:
        return

    content_type, text = extract_content(message)
    sender = getattr(message, "from_user", None)
    sender_id = int(sender.id) if sender is not None else None

    storage.biz_chat_touch(
        connection_id,
        int(chat.id),
        chat_title(chat),
        chat_type_of(chat),
    )
    storage.biz_message_store(
        connection_id=connection_id,
        chat_id=int(chat.id),
        message_id=int(message.message_id),
        sender_id=sender_id,
        sender_name=sender_name_of(sender),
        outgoing=(sender_id == owner_user_id),
        content_type=content_type,
        text=text,
        sent_at=_epoch(getattr(message, "date", None)),
    )


def mark_deleted(storage: Any, event: Any) -> List[Any]:
    """Помечает удалённые сообщения и возвращает их содержимое из архива."""
    return storage.biz_mark_deleted(
        connection_id=str(event.business_connection_id),
        chat_id=int(event.chat.id),
        message_ids=[int(m) for m in event.message_ids],
    )


# --------------------------------------------------------------------------- #
# Отчёты
# --------------------------------------------------------------------------- #
def build_deleted_report(chat_name: str, rows: List[Any]) -> str:
    """Уведомление «собеседник удалил сообщение» с текстом из архива."""
    lines = [f"🗑 <b>Удалено в чате «{_esc(chat_name)}»</b>", ""]
    for row in rows:
        who = _esc(row["sender_name"] or "без имени")
        direction = "вы" if row["outgoing"] else "собеседник"
        body = _esc(row["text"] or "")
        if len(body) > 900:
            body = body[:900] + "…"
        lines.append(f"<b>{who}</b> ({direction}), {_ts(float(row['sent_at']))}:")
        lines.append(f"<blockquote>{body}</blockquote>")
        lines.append("")
    lines.append("<i>Текст восстановлен из архива бота — Telegram не присылает содержимое удалённых сообщений.</i>")
    return "\n".join(lines)


def build_deleted_list(rows: List[Any], chat_titles: Dict[int, str]) -> str:
    if not rows:
        return "Удалённых сообщений в архиве нет."
    lines = ["🗑 <b>Удалённые сообщения</b>", ""]
    for row in rows:
        title = chat_titles.get(int(row["chat_id"]), str(row["chat_id"]))
        who = _esc(row["sender_name"] or "без имени")
        body = _esc(row["text"] or "")
        if len(body) > 200:
            body = body[:200] + "…"
        lines.append(f"• <b>{_esc(title)}</b> · {who} · {_ts(float(row['deleted_at']))}")
        lines.append(f"  <blockquote>{body}</blockquote>")
    return "\n".join(lines)


def build_chat_list(rows: List[Any]) -> str:
    if not rows:
        return (
            "Архив пуст.\n\n"
            "Подключите бота к аккаунту: Настройки → Telegram Business → Чат-боты.\n"
            "Бот видит только те чаты, которые вы ему откроете."
        )
    lines = ["💬 <b>Архив по чатам</b>", ""]
    for row in rows:
        title = _esc(row["title"] or str(row["chat_id"]))
        total = int(row["total"] or 0)
        deleted = int(row["deleted"] or 0)
        last = _ts(float(row["last_at"])) if row["last_at"] else "—"
        lines.append(f"• <b>{title}</b> — сообщений: {total}, удалено: {deleted}, последнее: {last}")
    return "\n".join(lines)


def build_status(storage: Any, owner_user_id: int) -> str:
    conns = storage.biz_connections_for(owner_user_id)
    if not conns:
        return (
            "🔌 <b>Business-логирование не подключено</b>\n\n"
            "1. В @BotFather включите Secretary Mode (раньше назывался Business Mode):\n"
            "   /mybots → бот → Bot Settings → Mode Settings → Secretary Mode → Turn on\n"
            "2. В Telegram: Настройки → Telegram Business → Чат-боты → выберите бота.\n"
            "3. Разрешите боту читать сообщения и удалять их.\n\n"
            "Проверка: /bizstatus должен показать подключение с ID.\n"
            "После подключения бот начнёт вести архив открытых вами чатов."
        )
    lines = ["🔌 <b>Business-подключения</b>", ""]
    for row in conns:
        cid = str(row["connection_id"])
        stats = storage.biz_stats(cid)
        state = "активно" if row["is_enabled"] else "отключено"
        lines.append(
            f"• <code>{_esc(cid)}</code> — {state}\n"
            f"  чатов: {stats['chats']}, сообщений: {stats['total']}, удалённых: {stats['deleted']}"
        )
        rights = (row["rights"] or "").strip()
        if rights:
            lines.append(f"  права: {_esc(rights)}")
        if not row["is_enabled"]:
            lines.append(
                "  ⚠️ Подключение отключено. Включите бота заново: "
                "Настройки → Telegram Business → Чат-боты."
            )
        elif rights and "чтение" not in rights:
            lines.append(
                "  ⚠️ Нет права читать сообщения — архив останется пустым. "
                "Выдайте: Настройки → Telegram Business → Чат-боты → ваш бот → Разрешения, "
                "затем переподключите бота."
            )
    return "\n".join(lines)


def build_digest(storage: Any, connection_id: str, since: float, until: float) -> str:
    """
    Недельная сводка по подключению: что происходило в открытых чатах.

    В сводку попадают счётчики и последние сообщения — полный архив остаётся
    в базе, а не уходит целиком в чат.
    """
    rows = storage.biz_messages_since(connection_id, since)
    deleted = storage.biz_deleted_since(connection_id, since)
    chats = storage.biz_chat_list(connection_id)

    lines = [
        "📊 <b>Недельная сводка по чатам</b>",
        f"Период: {_ts(since)} — {_ts(until)}",
        "",
        f"Сообщений за неделю: <b>{len(rows)}</b>",
        f"Удалено за неделю: <b>{len(deleted)}</b>",
        f"Активных чатов: <b>{len(chats)}</b>",
        "",
    ]

    if chats:
        lines.append("<b>По чатам</b>")
        for row in chats[:20]:
            title = _esc(row["title"] or str(row["chat_id"]))
            lines.append(
                f"• {title} — всего {int(row['total'] or 0)}, удалено {int(row['deleted'] or 0)}"
            )
        lines.append("")

    if deleted:
        lines.append("<b>Удалённое за неделю</b>")
        for row in deleted[:20]:
            who = _esc(row["sender_name"] or "без имени")
            body = _esc(row["text"] or "")
            if len(body) > 200:
                body = body[:200] + "…"
            lines.append(f"• {who} · {_ts(float(row['deleted_at']))}")
            lines.append(f"  <blockquote>{body}</blockquote>")
        if len(deleted) > 20:
            lines.append(f"… и ещё {len(deleted) - 20}.")
        lines.append("")

    lines.append("<i>Полный архив хранится в базе бота. Выгрузить: /archive</i>")
    return "\n".join(lines)


def build_archive_json(storage: Any, connection_id: str) -> bytes:
    """
    Полная выгрузка архива подключения в JSON.

    Отдаётся только владельцу подключения по его же запросу — фоновой рассылки
    чужих переписок куда-либо модуль не делает.
    """
    chats = storage.biz_chat_list(connection_id)
    payload: Dict[str, Any] = {
        "connection_id": connection_id,
        "exported_at": datetime.now(tz=timezone.utc).isoformat(),
        "chats": [],
    }
    for row in chats:
        chat_id = int(row["chat_id"])
        messages = storage.biz_messages_since(connection_id, 0.0, chat_id=chat_id)
        payload["chats"].append(
            {
                "chat_id": chat_id,
                "title": row["title"] or str(chat_id),
                "chat_type": row["chat_type"] or "",
                "total": int(row["total"] or 0),
                "deleted": int(row["deleted"] or 0),
                "messages": [
                    {
                        "message_id": int(m["message_id"]),
                        "sender_id": m["sender_id"],
                        "sender_name": m["sender_name"],
                        "outgoing": bool(m["outgoing"]),
                        "content_type": m["content_type"],
                        "text": m["text"],
                        "sent_at": datetime.fromtimestamp(
                            float(m["sent_at"]), tz=timezone.utc
                        ).isoformat(),
                        "is_deleted": bool(m["is_deleted"]),
                    }
                    for m in messages
                ],
            }
        )
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


# --------------------------------------------------------------------------- #
# Фоновый цикл: недельные сводки и очистка по сроку хранения
# --------------------------------------------------------------------------- #
def _digest_due(now: datetime, weekday: int, hour: int) -> bool:
    return now.weekday() == weekday and now.hour == hour


async def digest_loop(storage: Any, bot: Any, cfg: Any, tick: int = LOOP_TICK_SECONDS) -> None:
    """
    Раз в тик проверяет: не пора ли отправить недельную сводку и не надо ли
    вычистить старое. Сводка уходит владельцу подключения в его личный чат
    с ботом, а не третьему лицу.
    """
    biz = cfg.business
    while True:
        try:
            await asyncio.sleep(tick)
        except asyncio.CancelledError:
            raise

        try:
            now_dt = datetime.now(tz=timezone.utc)
            now_ts = time.time()

            if biz.digest_enabled:
                for row in storage.biz_all_connections():
                    conn_id = str(row["connection_id"])
                    key = _DIGEST_SENT_KEY.format(conn=conn_id)
                    last = storage.setting_get(key)
                    # Не чаще одной сводки в неделю на подключение.
                    if last is not None and now_ts - float(last) < 6.5 * 86400:
                        continue
                    if not _digest_due(now_dt, biz.digest_weekday, biz.digest_hour_utc):
                        continue

                    target = row["user_chat_id"]
                    if not target:
                        continue
                    since = now_ts - 7 * 86400
                    text = build_digest(storage, conn_id, since, now_ts)
                    try:
                        for chunk in report_module.split_message(text):
                            await bot.send_message(int(target), chunk)
                        storage.setting_set(key, str(now_ts))
                        log.info("Недельная сводка отправлена (connection=%s)", conn_id)
                    except Exception:  # noqa: BLE001 — сбой отправки не должен ронять цикл
                        log.warning("Не удалось отправить сводку (connection=%s)", conn_id, exc_info=True)

            # Очистка старого архива — не чаще раза в сутки.
            last_prune = storage.setting_get(_PRUNE_KEY)
            if last_prune is None or now_ts - float(last_prune) > 86400:
                removed = storage.biz_prune(biz.retention_days)
                storage.setting_set(_PRUNE_KEY, str(now_ts))
                if removed:
                    log.info(
                        "Очищено сообщений старше %s дн.: %s", biz.retention_days, removed
                    )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 — фоновая задача обязана выживать
            log.warning("Ошибка в цикле Business-логирования", exc_info=True)


def digest_window(now_ts: Optional[float] = None) -> Tuple[float, float]:
    """Границы последней недели — для /digest_now."""
    until = now_ts if now_ts is not None else time.time()
    return until - 7 * 86400, until
