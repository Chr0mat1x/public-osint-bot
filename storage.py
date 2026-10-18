"""
storage.py — SQLite-хранилище: кэш ответов, дневной rate-limit и история запросов.

Таблицы:
  cache     — результаты поиска по нормализованному запросу, TTL 24 часа (настраивается)
  usage     — сколько запросов сделал пользователь за сутки (окно = календарные сутки UTC)
  history   — журнал запросов пользователя, нужен для /delete_me
  settings  — key/value для рантайм-настроек (например, смена провайдера через /setkey)

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

        self.conn.commit()
        return {
            "history": h,
            "usage": u,
            "cache": c,
            "watches": w,
            "snapshots": snapshots,
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
