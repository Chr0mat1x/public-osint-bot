"""
config.py — загрузка, валидация и первичная настройка конфигурации.

Логика:
  1. Пытаемся прочитать config.yaml.
  2. Если файла нет или в нём пустой bot_token — запускаем интерактивный мастер
     в терминале (вопросы через input()), после чего сохраняем config.yaml.
  3. Любое значение можно переопределить переменной окружения
     (BOT_TOKEN, SEARCH_API_KEY, GITHUB_TOKEN, PROXY_LIST) — это удобно для Docker/CI.

Секреты хранятся только локально в config.yaml. Файл добавлен в .gitignore.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List

import yaml

# Корень проекта и путь к файлу конфигурации.
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.yaml"
EXAMPLE_PATH = BASE_DIR / "config.example.yaml"

# Провайдеры поиска, которые поддерживает sources/search_engines.py.
# auto — без ключа: duckduckgo, при блокировке фолбэк на bing_html.
SUPPORTED_SEARCH_PROVIDERS = ("auto", "duckduckgo", "bing_html", "serpapi", "bing")

# Провайдеры, которым обязательно нужен SEARCH_API_KEY.
PROVIDERS_REQUIRING_KEY = ("serpapi", "bing")


# --------------------------------------------------------------------------- #
# Секции конфигурации
# --------------------------------------------------------------------------- #
@dataclass
class TelegramConfig:
    bot_token: str = ""


@dataclass
class SearchConfig:
    provider: str = "auto"
    api_key: str = ""


@dataclass
class GithubConfig:
    token: str = ""


@dataclass
class MonitorConfig:
    """Фоновый мониторинг публичных реестров."""

    enabled: bool = True
    interval_hours: int = 6
    max_watches_per_user: int = 10


@dataclass
class BusinessConfig:
    """
    Логирование личных чатов через Telegram Business.

    Пользователь сам подключает бота к своему аккаунту
    (Настройки → Профиль → Автоматизация чатов). Бот видит только те чаты,
    которые владелец аккаунта ему открыл. Данные каждого подключения
    остаются у владельца этого подключения.

    Требует включённого Secretary Mode у бота в @BotFather.
    """

    enabled: bool = True
    notify_deletions: bool = True
    digest_enabled: bool = True
    digest_weekday: int = 6  # 0=Пн … 6=Вс; по умолчанию воскресенье
    digest_hour_utc: int = 20
    retention_days: int = 30


@dataclass
class NetworkConfig:
    proxy_list: List[str] = field(default_factory=list)
    request_timeout: float = 12.0
    source_timeout: float = 25.0
    max_concurrency: int = 8


@dataclass
class LimitsConfig:
    daily_requests_per_user: int = 10
    cache_ttl_hours: int = 24
    max_results_per_source: int = 20


@dataclass
class StorageConfig:
    db_path: str = "data/osint.sqlite3"


@dataclass
class AppConfig:
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    search: SearchConfig = field(default_factory=SearchConfig)
    github: GithubConfig = field(default_factory=GithubConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    business: BusinessConfig = field(default_factory=BusinessConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)

    # -- сериализация ------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, path: Path = CONFIG_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(
                self.to_dict(), fh, allow_unicode=True, sort_keys=False, default_flow_style=False
            )
        # config.yaml содержит токены — держим права только для владельца.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    @property
    def db_path_abs(self) -> Path:
        p = Path(self.storage.db_path)
        return p if p.is_absolute() else BASE_DIR / p


def _section(data: Dict[str, Any], key: str) -> Dict[str, Any]:
    value = data.get(key)
    return value if isinstance(value, dict) else {}


def load_config(path: Path = CONFIG_PATH) -> AppConfig:
    """Читает YAML и накладывает поверх него переменные окружения."""
    raw: Dict[str, Any] = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raw = {}

    tg = _section(raw, "telegram")
    srch = _section(raw, "search")
    gh = _section(raw, "github")
    mon = _section(raw, "monitor")
    biz = _section(raw, "business")
    net = _section(raw, "network")
    lim = _section(raw, "limits")
    sto = _section(raw, "storage")

    cfg = AppConfig(
        telegram=TelegramConfig(bot_token=str(tg.get("bot_token") or "")),
        search=SearchConfig(
            provider=str(srch.get("provider") or "auto").lower(),
            api_key=str(srch.get("api_key") or ""),
        ),
        github=GithubConfig(token=str(gh.get("token") or "")),
        monitor=MonitorConfig(
            enabled=bool(mon.get("enabled", True)),
            interval_hours=int(mon.get("interval_hours") or 6),
            max_watches_per_user=int(mon.get("max_watches_per_user") or 10),
        ),
        business=BusinessConfig(
            enabled=bool(biz.get("enabled", True)),
            notify_deletions=bool(biz.get("notify_deletions", True)),
            digest_enabled=bool(biz.get("digest_enabled", True)),
            digest_weekday=int(biz.get("digest_weekday", 6)),
            digest_hour_utc=int(biz.get("digest_hour_utc", 20)),
            retention_days=int(biz.get("retention_days") or 30),
        ),
        network=NetworkConfig(
            proxy_list=list(net.get("proxy_list") or []),
            request_timeout=float(net.get("request_timeout") or 12.0),
            source_timeout=float(net.get("source_timeout") or 25.0),
            max_concurrency=int(net.get("max_concurrency") or 8),
        ),
        limits=LimitsConfig(
            daily_requests_per_user=int(lim.get("daily_requests_per_user") or 10),
            cache_ttl_hours=int(lim.get("cache_ttl_hours") or 24),
            max_results_per_source=int(lim.get("max_results_per_source") or 20),
        ),
        storage=StorageConfig(db_path=str(sto.get("db_path") or "data/osint.sqlite3")),
    )

    # Переопределения из окружения (пустая строка НЕ затирает значение из файла).
    cfg.telegram.bot_token = os.getenv("BOT_TOKEN") or cfg.telegram.bot_token
    cfg.search.api_key = os.getenv("SEARCH_API_KEY") or cfg.search.api_key
    cfg.github.token = os.getenv("GITHUB_TOKEN") or cfg.github.token
    env_proxies = os.getenv("PROXY_LIST")
    if env_proxies:
        cfg.network.proxy_list = [p.strip() for p in env_proxies.split(",") if p.strip()]

    env_biz = os.getenv("BUSINESS_ENABLED")
    if env_biz is not None and env_biz.strip():
        cfg.business.enabled = env_biz.strip().lower() in ("1", "true", "yes", "on")

    return cfg


def validate_config(cfg: AppConfig) -> List[str]:
    """Возвращает список проблем. Пустой список = конфиг пригоден для запуска."""
    problems: List[str] = []
    if not cfg.telegram.bot_token or ":" not in cfg.telegram.bot_token:
        problems.append("telegram.bot_token не задан или имеет неверный формат (нужно '123456:AA...').")
    if cfg.search.provider not in SUPPORTED_SEARCH_PROVIDERS:
        problems.append(
            f"search.provider='{cfg.search.provider}' не поддерживается. "
            f"Допустимо: {', '.join(SUPPORTED_SEARCH_PROVIDERS)}."
        )
    if cfg.search.provider in PROVIDERS_REQUIRING_KEY and not cfg.search.api_key:
        problems.append(f"Для провайдера '{cfg.search.provider}' нужен search.api_key.")
    if cfg.limits.daily_requests_per_user < 1:
        problems.append("limits.daily_requests_per_user должен быть >= 1.")
    if not 0 <= cfg.business.digest_weekday <= 6:
        problems.append("business.digest_weekday должен быть в диапазоне 0..6 (0=Пн).")
    if not 0 <= cfg.business.digest_hour_utc <= 23:
        problems.append("business.digest_hour_utc должен быть в диапазоне 0..23.")
    if cfg.business.retention_days < 1:
        problems.append("business.retention_days должен быть >= 1.")
    return problems


# --------------------------------------------------------------------------- #
# Интерактивный мастер первого запуска
# --------------------------------------------------------------------------- #
def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        answer = input(f"{prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise SystemExit("Настройка прервана. Запустите `python bot.py` снова.")
    return answer or default


def run_setup_wizard(cfg: AppConfig, path: Path = CONFIG_PATH) -> AppConfig:
    """Спрашивает ключи в терминале и сохраняет config.yaml."""
    print("=" * 62)
    print(" Первый запуск: настройка OSINT-бота (только публичные данные)")
    print("=" * 62)
    print("Пустой ввод оставляет значение в скобках / пропускает опциональный пункт.\n")

    cfg.telegram.bot_token = _ask("BOT_TOKEN (от @BotFather)", cfg.telegram.bot_token)

    provider = _ask(
        f"Поисковый провайдер ({'/'.join(SUPPORTED_SEARCH_PROVIDERS)})",
        cfg.search.provider,
    ).lower()
    cfg.search.provider = provider if provider in SUPPORTED_SEARCH_PROVIDERS else "auto"

    if cfg.search.provider in PROVIDERS_REQUIRING_KEY:
        cfg.search.api_key = _ask("SEARCH_API_KEY", cfg.search.api_key)
    else:
        # auto/duckduckgo/bing_html работают без ключа.
        print(f"'{cfg.search.provider}' работает без ключа — SEARCH_API_KEY не требуется.")

    gh = _ask("GITHUB_TOKEN (опционально, Enter — пропустить)", cfg.github.token)
    cfg.github.token = gh

    proxies = _ask(
        "PROXY_LIST (опционально, через запятую, Enter — пропустить)",
        ",".join(cfg.network.proxy_list),
    )
    cfg.network.proxy_list = [p.strip() for p in proxies.split(",") if p.strip()]

    biz = _ask(
        "Логировать личные чаты через Telegram Business (да/нет)",
        "да" if cfg.business.enabled else "нет",
    ).lower()
    cfg.business.enabled = biz in ("да", "yes", "y", "1", "true", "on")
    if cfg.business.enabled:
        print(
            "  Не забудьте включить Secretary Mode у бота в @BotFather:\n"
            "  /mybots → выберите бота → Bot Settings → Mode Settings → Secretary Mode → Turn on."
        )

    cfg.save(path)
    print(f"\nКонфигурация сохранена: {path}")
    print("Файл содержит секреты и уже добавлен в .gitignore.\n")
    return cfg


def ensure_config() -> AppConfig:
    """
    Точка входа для bot.py: вернуть валидный конфиг, при необходимости
    проведя пользователя через мастер настройки.
    """
    cfg = load_config()

    if not cfg.telegram.bot_token:
        cfg = run_setup_wizard(cfg)

    problems = validate_config(cfg)
    if problems:
        # Пытаемся дозаполнить недостающее в диалоге, затем проверяем ещё раз.
        print("Проблемы в конфигурации:")
        for p in problems:
            print(f"  - {p}")
        print()
        cfg = run_setup_wizard(cfg)
        problems = validate_config(cfg)

    if problems:
        raise SystemExit("Конфигурация не готова к запуску:\n  - " + "\n  - ".join(problems))

    return cfg
