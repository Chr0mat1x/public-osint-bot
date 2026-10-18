"""
storage.py — SQLite-хранилище: кэш ответов, дневной rate-limit и история запросов.

Таблицы:
  cache     — результаты поиска по нормализованному запросу, TTL 24 часа (настраивается)
  usage     — сколько запросов сделал пользователь за сутки (окно = календарные сутки UTC)
  history   — журнал запросов пользователя, нужен для /delete_me
  settings  — key/value для рантайм-настроек (например, смена провайдера через /setkey)
  watches   — наблюдения за публичными реестрами (мониторинг)
  snapshots — снимки состояния наблюдений для вычисления изменений
  business_connections — подключения Telegram Business (владелец аккаунта)
  chat_meta            — известные чаты подключения
  chat_messages        — архив переписки, включая удалённые сообщения

Всё хранится локально, во внешние сервисы ничего не отправляется.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key         TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS usage (
    user_id     INTEGER NOT NULL,
    day         TEXT    NOT NULL,
    count       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
);

CREATE TABLE IF NOT EXISTS history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    query       TEXT    NOT NULL,
    created_at  REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_history_user ON history(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS watches (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    subject     TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    last_check  REAL,
    UNIQUE(user_id, subject, kind)
);

CREATE INDEX IF NOT EXISTS idx_watches_user ON watches(user_id);

CREATE TABLE IF NOT EXISTS snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    watch_id    INTEGER NOT NULL,
    fingerprint TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    created_at  REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_watch ON snapshots(watch_id, created_at DESC);

-- ------------------------------------------------------------------ --
-- Логирование личных чатов через Telegram Business.
-- Владелец аккаунта сам подключает бота и сам выбирает, какие чаты ему
-- открыть. Данные каждого подключения изолированы по connection_id и
-- доступны только владельцу этого подключения.
-- ------------------------------------------------------------------ --
CREATE TABLE IF NOT EXISTS business_connections (
    connection_id TEXT PRIMARY KEY,
    owner_user_id INTEGER NOT NULL,
    user_chat_id  INTEGER,
    is_enabled    INTEGER NOT NULL DEFAULT 1,
    connected_at  REAL    NOT NULL,
    updated_at    REAL    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_biz_conn_owner ON business_connections(owner_user_id);

CREATE TABLE IF NOT EXISTS chat_meta (
    connection_id TEXT    NOT NULL,
    chat_id       INTEGER NOT NULL,
    title         TEXT    NOT NULL DEFAULT '',
    chat_type     TEXT    NOT NULL DEFAULT '',
    updated_at    REAL    NOT NULL,
    PRIMARY KEY (connection_id, chat_id)
);

CREATE TABLE IF NOT EXISTS chat_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT    NOT NULL,
    chat_id       INTEGER NOT NULL,
    message_id    INTEGER NOT NULL,
    sender_id     INTEGER,
    sender_name   TEXT    NOT NULL DEFAULT '',
    outgoing      INTEGER NOT NULL DEFAULT 0,
    content_type  TEXT    NOT NULL DEFAULT 'text',
    text          TEXT    NOT NULL DEFAULT '',
    sent_at       REAL    NOT NULL,
    edited_at     REAL,
    is_deleted    INTEGER NOT NULL DEFAULT 0,
    deleted_at    REAL,
    UNIQUE(connection_id, chat_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_messages_chat
    ON chat_messages(connection_id, chat_id, sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_messages_deleted
    ON chat_messages(connection_id, is_deleted, deleted_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_messages_sent ON chat_messages(sent_at);
"""


class Storage:
    def __init__(self, db_path: Path | str, cache_ttl_hours: int = 24) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_ttl_seconds = int(cache_ttl_hours * 3600)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # WAL + NORMAL — бот однопоточный по логике, но aiogram может дергать из задач.
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        try:
            self.conn.close()
        except sqlite3.Error:
            pass

    # ------------------------------------------------------------------ #
    # Кэш
    # ------------------------------------------------------------------ #
    def cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        """Вернуть payload, если запись существует и не старше TTL. Иначе None."""
        row = self.conn.execute(
            "SELECT payload, created_at FROM cache WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if time.time() - float(row["created_at"]) > self.cache_ttl_seconds:
            self.conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self.conn.commit()
            return None
        try:
            return json.loads(row["payload"])
        except json.JSONDecodeError:
            # Битый payload — считаем кэш промахом и вычищаем запись.
            self.conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            self.conn.commit()
            return None

    def cache_set(self, key: str, payload: Dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO cache(key, payload, created_at) VALUES(?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET payload = excluded.payload, "
            "created_at = excluded.created_at",
            (key, json.dumps(payload, ensure_ascii=False), time.time()),
        )
        self.conn.commit()

    def cache_purge_expired(self) -> int:
        cutoff = time.time() - self.cache_ttl_seconds
        cur = self.conn.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))
        self.conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------------------ #
    # Rate-limit
    # ------------------------------------------------------------------ #
    @staticmethod
    def _today() -> str:
        # Сутки считаем по UTC, чтобы поведение не зависело от TZ сервера.
        return time.strftime("%Y-%m-%d", time.gmtime())

    def usage_today(self, user_id: int) -> int:
        row = self.conn.execute(
            "SELECT count FROM usage WHERE user_id = ? AND day = ?",
            (user_id, self._today()),
        ).fetchone()
        return int(row["count"]) if row else 0

    def usage_remaining(self, user_id: int, daily_limit: int) -> int:
        return max(0, daily_limit - self.usage_today(user_id))

    def try_consume_quota(self, user_id: int, daily_limit: int) -> bool:
        """
        Атомарно списать одну попытку. True — можно выполнять запрос.
        Используем UPSERT с условием в WHERE, чтобы не гонять гонки.
        """
        day = self._today()
        cur = self.conn.execute(
            """
            INSERT INTO usage(user_id, day, count) VALUES(?, ?, 1)
            ON CONFLICT(user_id, day) DO UPDATE SET count = count + 1
                WHERE usage.count < ?
            """,
            (user_id, day, daily_limit),
        )
        self.conn.commit()
        # rowcount == 0 означает, что условие WHERE не сработало → лимит исчерпан.
        return (cur.rowcount or 0) > 0

    def reset_usage(self, user_id: int) -> None:
        self.conn.execute("DELETE FROM usage WHERE user_id = ?", (user_id,))
        self.conn.commit()

    # ------------------------------------------------------------------ #
    # История и удаление
    # ------------------------------------------------------------------ #
    def history_add(self, user_id: int, query: str) -> None:
        self.conn.execute(
            "INSERT INTO history(user_id, query, created_at) VALUES(?, ?, ?)",
            (user_id, query, time.time()),
        )
        self.conn.commit()

    def history_list(self, user_id: int, limit: int = 10) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT query, created_at FROM history WHERE user_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            ).fetchall()
        )

    def delete_user(self, user_id: int) -> Dict[str, int]:
        """Полное удаление данных пользователя: история + счётчик + кэш + наблюдения."""
        h = self.conn.execute("DELETE FROM history WHERE user_id = ?", (user_id,)).rowcount or 0
        u = self.conn.execute("DELETE FROM usage WHERE user_id = ?", (user_id,)).rowcount or 0
        # Ключи кэша имеют префикс "u<user_id>:" — чистим только свои записи.
        c = self.conn.execute("DELETE FROM cache WHERE key LIKE ?", (f"u{user_id}:%",)).rowcount or 0

        # Наблюдения: сначала снимки (дочерние записи), потом сами наблюдения.
        watch_ids = [
            row["id"]
            for row in self.conn.execute(
                "SELECT id FROM watches WHERE user_id = ?", (user_id,)
            ).fetchall()
        ]
        snapshots = 0
        for watch_id in watch_ids:
            snapshots += (
                self.conn.execute(
                    "DELETE FROM snapshots WHERE watch_id = ?", (watch_id,)
                ).rowcount
                or 0
            )
        w = (
            self.conn.execute("DELETE FROM watches WHERE user_id = ?", (user_id,)).rowcount
            or 0
        )

        # Business-подключения пользователя: сообщения и метаданные чатов
        # удаляются вместе с подключением.
        conn_ids = [
            row["connection_id"]
            for row in self.conn.execute(
                "SELECT connection_id FROM business_connections WHERE owner_user_id = ?",
                (user_id,),
            ).fetchall()
        ]
        biz_messages = 0
        biz_chats = 0
        for cid in conn_ids:
            biz_messages += (
                self.conn.execute(
                    "DELETE FROM chat_messages WHERE connection_id = ?", (cid,)
                ).rowcount
                or 0
            )
            biz_chats += (
                self.conn.execute(
                    "DELETE FROM chat_meta WHERE connection_id = ?", (cid,)
                ).rowcount
                or 0
            )
        biz_connections = (
            self.conn.execute(
                "DELETE FROM business_connections WHERE owner_user_id = ?", (user_id,)
            ).rowcount
            or 0
        )

        self.conn.commit()
        return {
            "history": h,
            "usage": u,
            "cache": c,
            "watches": w,
            "snapshots": snapshots,
            "biz_connections": biz_connections,
            "biz_messages": biz_messages,
            "biz_chats": biz_chats,
        }

    # ------------------------------------------------------------------ #
    # Рантайм-настройки
    # ------------------------------------------------------------------ #
    def setting_get(self, key: str) -> Optional[str]:
        row = self.conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def setting_set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    # ------------------------------------------------------------------ #
    # Наблюдения (мониторинг публичных реестров)
    # ------------------------------------------------------------------ #
    def watch_add(self, user_id: int, subject: str, kind: str) -> int:
        """Добавляет наблюдение. Возвращает id (существующего или нового)."""
        cur = self.conn.execute(
            "INSERT INTO watches(user_id, subject, kind, created_at) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(user_id, subject, kind) DO UPDATE SET subject = excluded.subject",
            (user_id, subject.strip(), kind.strip(), time.time()),
        )
        self.conn.commit()
        row = self.conn.execute(
            "SELECT id FROM watches WHERE user_id = ? AND subject = ? AND kind = ?",
            (user_id, subject.strip(), kind.strip()),
        ).fetchone()
        return int(row["id"]) if row else (cur.lastrowid or 0)

    def watch_list(self, user_id: int) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT id, subject, kind, created_at, last_check FROM watches "
                "WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            ).fetchall()
        )

    def watch_all(self) -> List[sqlite3.Row]:
        """Все наблюдения всех пользователей — для фонового обхода."""
        return list(
            self.conn.execute(
                "SELECT id, user_id, subject, kind FROM watches ORDER BY id"
            ).fetchall()
        )

    def watch_remove(self, user_id: int, subject: str) -> int:
        rows = self.conn.execute(
            "SELECT id FROM watches WHERE user_id = ? AND subject = ?",
            (user_id, subject.strip()),
        ).fetchall()
        for row in rows:
            self.conn.execute("DELETE FROM snapshots WHERE watch_id = ?", (row["id"],))
        cur = self.conn.execute(
            "DELETE FROM watches WHERE user_id = ? AND subject = ?", (user_id, subject.strip())
        )
        self.conn.commit()
        return cur.rowcount or 0

    def watch_touch(self, watch_id: int) -> None:
        self.conn.execute(
            "UPDATE watches SET last_check = ? WHERE id = ?", (time.time(), watch_id)
        )
        self.conn.commit()

    def snapshot_last(self, watch_id: int) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT fingerprint, payload, created_at FROM snapshots "
            "WHERE watch_id = ? ORDER BY created_at DESC LIMIT 1",
            (watch_id,),
        ).fetchone()

    def snapshot_add(self, watch_id: int, fingerprint: str, payload: Dict[str, Any]) -> None:
        self.conn.execute(
            "INSERT INTO snapshots(watch_id, fingerprint, payload, created_at) VALUES(?, ?, ?, ?)",
            (watch_id, fingerprint, json.dumps(payload, ensure_ascii=False), time.time()),
        )
        self.conn.commit()

    def snapshot_prune(self, watch_id: int, keep: int = 10) -> int:
        """Оставляет только последние N снимков, чтобы БД не росла бесконечно."""
        cur = self.conn.execute(
            "DELETE FROM snapshots WHERE watch_id = ? AND id NOT IN "
            "(SELECT id FROM snapshots WHERE watch_id = ? ORDER BY created_at DESC LIMIT ?)",
            (watch_id, watch_id, keep),
        )
        self.conn.commit()
        return cur.rowcount or 0

    # ------------------------------------------------------------------ #
    # Telegram Business: подключения, чаты, сообщения
    # ------------------------------------------------------------------ #
    def biz_connection_upsert(
        self,
        connection_id: str,
        owner_user_id: int,
        user_chat_id: Optional[int],
        is_enabled: bool,
    ) -> None:
        now = time.time()
        self.conn.execute(
            """
            INSERT INTO business_connections
                (connection_id, owner_user_id, user_chat_id, is_enabled, connected_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(connection_id) DO UPDATE SET
                owner_user_id = excluded.owner_user_id,
                user_chat_id  = excluded.user_chat_id,
                is_enabled    = excluded.is_enabled,
                updated_at    = excluded.updated_at
            """,
            (connection_id, owner_user_id, user_chat_id, int(is_enabled), now, now),
        )
        self.conn.commit()

    def biz_connection_owner(self, connection_id: str) -> Optional[int]:
        """Владелец подключения — единственный, кто получает его данные."""
        row = self.conn.execute(
            "SELECT owner_user_id FROM business_connections WHERE connection_id = ?",
            (connection_id,),
        ).fetchone()
        return int(row["owner_user_id"]) if row else None

    def biz_connection_enabled(self, connection_id: str) -> bool:
        row = self.conn.execute(
            "SELECT is_enabled FROM business_connections WHERE connection_id = ?",
            (connection_id,),
        ).fetchone()
        return bool(row["is_enabled"]) if row else False

    def biz_connection_set_enabled(self, connection_id: str, is_enabled: bool) -> None:
        self.conn.execute(
            "UPDATE business_connections SET is_enabled = ?, updated_at = ? WHERE connection_id = ?",
            (int(is_enabled), time.time(), connection_id),
        )
        self.conn.commit()

    def biz_connections_for(self, owner_user_id: int) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT connection_id, user_chat_id, is_enabled, connected_at "
                "FROM business_connections WHERE owner_user_id = ? ORDER BY connected_at DESC",
                (owner_user_id,),
            ).fetchall()
        )

    def biz_all_connections(self) -> List[sqlite3.Row]:
        """Все активные подключения — для фоновой рассылки сводок."""
        return list(
            self.conn.execute(
                "SELECT connection_id, owner_user_id, user_chat_id FROM business_connections "
                "WHERE is_enabled = 1 ORDER BY owner_user_id"
            ).fetchall()
        )

    def biz_chat_touch(
        self, connection_id: str, chat_id: int, title: str, chat_type: str
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO chat_meta(connection_id, chat_id, title, chat_type, updated_at)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(connection_id, chat_id) DO UPDATE SET
                title      = excluded.title,
                chat_type  = excluded.chat_type,
                updated_at = excluded.updated_at
            """,
            (connection_id, chat_id, title, chat_type, time.time()),
        )
        self.conn.commit()

    def biz_message_store(
        self,
        connection_id: str,
        chat_id: int,
        message_id: int,
        sender_id: Optional[int],
        sender_name: str,
        outgoing: bool,
        content_type: str,
        text: str,
        sent_at: float,
    ) -> None:
        """
        Сохраняет сообщение. Повторный апдейт (правка) обновляет текст и
        время правки, но не сбрасывает отметку об удалении.
        """
        self.conn.execute(
            """
            INSERT INTO chat_messages
                (connection_id, chat_id, message_id, sender_id, sender_name,
                 outgoing, content_type, text, sent_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(connection_id, chat_id, message_id) DO UPDATE SET
                text         = excluded.text,
                content_type = excluded.content_type,
                edited_at    = ?
            """,
            (
                connection_id,
                chat_id,
                message_id,
                sender_id,
                sender_name,
                int(outgoing),
                content_type,
                text,
                sent_at,
                time.time(),
            ),
        )
        self.conn.commit()

    def biz_message_get(
        self, connection_id: str, chat_id: int, message_id: int
    ) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT message_id, sender_id, sender_name, outgoing, content_type, text, sent_at "
            "FROM chat_messages WHERE connection_id = ? AND chat_id = ? AND message_id = ?",
            (connection_id, chat_id, message_id),
        ).fetchone()

    def biz_mark_deleted(
        self, connection_id: str, chat_id: int, message_ids: List[int]
    ) -> List[sqlite3.Row]:
        """
        Помечает сообщения удалёнными и возвращает их содержимое.

        Именно этот метод даёт ответ на «что собеседник удалил»: текст
        берётся из архива, который бот записал до удаления.
        """
        if not message_ids:
            return []
        placeholders = ",".join("?" for _ in message_ids)
        rows = list(
            self.conn.execute(
                f"SELECT message_id, sender_id, sender_name, outgoing, content_type, text, sent_at "
                f"FROM chat_messages WHERE connection_id = ? AND chat_id = ? "
                f"AND message_id IN ({placeholders})",
                (connection_id, chat_id, *message_ids),
            ).fetchall()
        )
        now = time.time()
        self.conn.execute(
            f"UPDATE chat_messages SET is_deleted = 1, deleted_at = ? "
            f"WHERE connection_id = ? AND chat_id = ? AND message_id IN ({placeholders})",
            (now, connection_id, chat_id, *message_ids),
        )
        self.conn.commit()
        return rows

    def biz_chat_list(self, connection_id: str) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT m.chat_id,
                       COALESCE(c.title, '') AS title,
                       COALESCE(c.chat_type, '') AS chat_type,
                       COUNT(*) AS total,
                       SUM(CASE WHEN m.is_deleted = 1 THEN 1 ELSE 0 END) AS deleted,
                       MAX(m.sent_at) AS last_at
                FROM chat_messages m
                LEFT JOIN chat_meta c
                       ON c.connection_id = m.connection_id AND c.chat_id = m.chat_id
                WHERE m.connection_id = ?
                GROUP BY m.chat_id
                ORDER BY last_at DESC
                """,
                (connection_id,),
            ).fetchall()
        )

    def biz_messages_since(
        self, connection_id: str, since: float, chat_id: Optional[int] = None
    ) -> List[sqlite3.Row]:
        sql = (
            "SELECT chat_id, message_id, sender_id, sender_name, outgoing, content_type, "
            "text, sent_at, is_deleted FROM chat_messages "
            "WHERE connection_id = ? AND sent_at >= ?"
        )
        params: List[Any] = [connection_id, since]
        if chat_id is not None:
            sql += " AND chat_id = ?"
            params.append(chat_id)
        sql += " ORDER BY sent_at ASC"
        return list(self.conn.execute(sql, tuple(params)).fetchall())

    def biz_deleted_since(
        self, connection_id: str, since: float
    ) -> List[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT chat_id, message_id, sender_name, outgoing, content_type, text, "
                "sent_at, deleted_at FROM chat_messages "
                "WHERE connection_id = ? AND is_deleted = 1 AND deleted_at >= ? "
                "ORDER BY deleted_at ASC",
                (connection_id, since),
            ).fetchall()
        )

    def biz_stats(self, connection_id: str) -> Dict[str, int]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN is_deleted = 1 THEN 1 ELSE 0 END) AS deleted, "
            "COUNT(DISTINCT chat_id) AS chats "
            "FROM chat_messages WHERE connection_id = ?",
            (connection_id,),
        ).fetchone()
        return {
            "total": int(row["total"] or 0),
            "deleted": int(row["deleted"] or 0),
            "chats": int(row["chats"] or 0),
        }

    def biz_prune(self, retention_days: int) -> int:
        """
        Удаляет переписку старше retention_days. Отдельно чистит метаданные
        чатов, в которых не осталось сообщений.
        """
        cutoff = time.time() - retention_days * 86400
        cur = self.conn.execute("DELETE FROM chat_messages WHERE sent_at < ?", (cutoff,))
        removed = cur.rowcount or 0
        self.conn.execute(
            "DELETE FROM chat_meta WHERE NOT EXISTS ("
            "SELECT 1 FROM chat_messages m WHERE m.connection_id = chat_meta.connection_id "
            "AND m.chat_id = chat_meta.chat_id)"
        )
        self.conn.commit()
        return removed
