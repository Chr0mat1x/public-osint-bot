"""
bot.py — точка входа Telegram-бота.

Запуск:
    python bot.py

При первом запуске, если config.yaml нет или в нём пустой токен, бот проведёт
интерактивный мастер настройки в терминале и сохранит ключи локально.

Команды:
    /find <username> [имя]  — поиск по публичным источникам
    /limits                 — остаток дневного лимита
    /history                — последние запросы пользователя
    /delete_me              — удалить историю, счётчики и кэш пользователя
    /setkey                 — сменить поисковый провайдер/ключ (только владелец)
    /help                   — справка

Ограничения зашиты в код: 10 запросов/сутки на пользователя, кэш 24 часа,
только публичные страницы без авторизации и обхода капчи.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramNetworkError, TelegramUnauthorizedError
from aiogram.filters import Command, CommandObject
from aiogram.types import BufferedInputFile, LinkPreviewOptions, Message

import config as config_module
import evidence as evidence_module
import monitor as monitor_module
import report as report_module
import selftrace as selftrace_module
from config import AppConfig
from normalizer import Query, build_query, normalize_username
from orchestrator import outcome_from_cache, outcome_to_cache, run_search
from sources import SourceContext
from sources import breach_public as breach_module
from sources.http_client import HttpClient
from storage import Storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
)
log = logging.getLogger("osint-bot")

router = Router()
NO_PREVIEW = LinkPreviewOptions(is_disabled=True)

# Заполняются в main() — так проще, чем таскать объекты через замыкания.
storage: Storage
app_cfg: AppConfig
http_client: HttpClient

# Последний собранный доказательный пакет: нужен для /evidence_json.
# Хранится в памяти процесса, ключ — user_id (пакет содержит только публичные данные).
_last_pack: dict[int, "evidence_module.EvidencePack"] = {}


# --------------------------------------------------------------------------- #
# Вспомогательные функции
# --------------------------------------------------------------------------- #
async def send_long(message: Message, text: str) -> None:
    """Отправляет отчёт, разбивая его на части по лимиту Telegram."""
    for chunk in report_module.split_message(text):
        await message.answer(chunk, link_preview_options=NO_PREVIEW)


def quota_note(user_id: int) -> str:
    remaining = storage.usage_remaining(user_id, app_cfg.limits.daily_requests_per_user)
    return f"Осталось запросов сегодня: {remaining}/{app_cfg.limits.daily_requests_per_user}."


async def is_owner(user_id: int) -> bool:
    """
    Владелец = первый пользователь, написавший боту (id сохраняется в БД).
    Нужен, чтобы менять провайдера/ключ мог только хозяин бота.
    """
    owner = storage.setting_get("owner_id")
    if owner is None:
        storage.setting_set("owner_id", str(user_id))
        return True
    return owner == str(user_id)


# --------------------------------------------------------------------------- #
# Основной сценарий поиска
# --------------------------------------------------------------------------- #
async def perform_search(message: Message, raw_query: str) -> None:
    user_id = message.from_user.id
    query: Query = build_query(raw_query)

    if not query.username and not query.full_name:
        await message.answer(
            "Не понял запрос. Пришлите username, например: <code>/find ivan_petrov</code> "
            "или <code>ivan_petrov Иван Петров</code>.",
            link_preview_options=NO_PREVIEW,
        )
        return

    cache_key = f"u{user_id}:{query.cache_key()}"

    # 1. Кэш. Попадание в кэш не тратит дневную квоту — это не новый поход в источники.
    cached = storage.cache_get(cache_key)
    if cached is not None:
        outcome = outcome_from_cache(query, cached)
        outcome.query = query
        await send_long(message, report_module.build_report(outcome))
        return

    # 2. Дневной rate-limit.
    if not storage.try_consume_quota(user_id, app_cfg.limits.daily_requests_per_user):
        await message.answer(
            f"⛔️ Дневной лимит исчерпан "
            f"({app_cfg.limits.daily_requests_per_user} запросов/сутки).\n"
            f"Кэш живёт {app_cfg.limits.cache_ttl_hours} ч, лимит обновится в 00:00 UTC.\n"
            "Историю можно удалить командой /delete_me.",
            link_preview_options=NO_PREVIEW,
        )
        return

    storage.history_add(user_id, query.raw)

    status = await message.answer(
        f"🔍 Ищу публичные следы по <code>{query.username or query.raw}</code>…\n"
        f"{quota_note(user_id)}",
        link_preview_options=NO_PREVIEW,
    )

    ctx = SourceContext(
        http=http_client,
        search_provider=app_cfg.search.provider,
        search_api_key=app_cfg.search.api_key,
        github_token=app_cfg.github.token,
        max_results=app_cfg.limits.max_results_per_source,
    )

    try:
        outcome = await run_search(
            query,
            ctx,
            source_timeout=app_cfg.network.source_timeout,
            overall_timeout=app_cfg.network.source_timeout + 10,
        )
    except Exception as exc:  # noqa: BLE001 — бот не должен падать из-за источника
        log.exception("Поиск упал целиком")
        await status.edit_text(f"❌ Внутренняя ошибка поиска: {type(exc).__name__}: {exc}")
        return

    # 3. Сохраняем результат в кэш на 24 часа.
    try:
        storage.cache_set(cache_key, outcome_to_cache(outcome))
    except Exception:  # noqa: BLE001 — кэш не критичен для ответа
        log.warning("Не удалось сохранить результат в кэш", exc_info=True)

    text = report_module.build_report(outcome)

    try:
        await status.delete()
    except Exception:  # noqa: BLE001 — сообщение могло быть уже удалено
        pass

    await send_long(message, text)


# --------------------------------------------------------------------------- #
# Хэндлеры
# --------------------------------------------------------------------------- #
@router.message(Command("start", "help"))
async def cmd_help(message: Message) -> None:
    await is_owner(message.from_user.id)
    await message.answer(report_module.build_help(), link_preview_options=NO_PREVIEW)


@router.message(Command("find"))
async def cmd_find(message: Message, command: CommandObject) -> None:
    raw = (command.args or "").strip()
    if not raw:
        await message.answer(
            "Формат: <code>/find username [Имя Фамилия]</code>",
            link_preview_options=NO_PREVIEW,
        )
        return
    await perform_search(message, raw)


@router.message(Command("limits"))
async def cmd_limits(message: Message) -> None:
    user_id = message.from_user.id
    used = storage.usage_today(user_id)
    limit = app_cfg.limits.daily_requests_per_user
    await message.answer(
        "📊 <b>Лимиты и кэш</b>\n\n"
        f"Запросов сегодня: {used}/{limit}\n"
        f"Кэш: {app_cfg.limits.cache_ttl_hours} ч, SQLite\n"
        f"Провайдер поиска: <code>{app_cfg.search.provider}</code>\n"
        f"Прокси: {len(app_cfg.network.proxy_list)} шт.\n"
        f"Таймауты: запрос {app_cfg.network.request_timeout:.0f} с, источник {app_cfg.network.source_timeout:.0f} с\n"
        f"Лимит находок на источник: {app_cfg.limits.max_results_per_source}\n"
        f"Наблюдений: {len(storage.watch_list(user_id))}/{app_cfg.monitor.max_watches_per_user}\n"
        f"Мониторинг: {'каждые ' + str(app_cfg.monitor.interval_hours) + ' ч' if app_cfg.monitor.enabled else 'выключен'}\n"
        f"HIBP-ключ (проверка e-mail): {'есть' if app_cfg.hibp.api_key else 'нет'}",
        link_preview_options=NO_PREVIEW,
    )


@router.message(Command("history"))
async def cmd_history(message: Message) -> None:
    rows = storage.history_list(message.from_user.id, limit=10)
    if not rows:
        await message.answer("История пуста.", link_preview_options=NO_PREVIEW)
        return
    lines = ["🗂 <b>Последние запросы</b>", ""]
    for row in rows:
        lines.append(f"• <code>{row['query']}</code>")
    lines.append("")
    lines.append("Удалить всё: /delete_me")
    await message.answer("\n".join(lines), link_preview_options=NO_PREVIEW)


@router.message(Command("delete_me"))
async def cmd_delete_me(message: Message) -> None:
    stats = storage.delete_user(message.from_user.id)
    _last_pack.pop(message.from_user.id, None)
    await message.answer(
        "🧹 <b>Данные удалены</b>\n\n"
        f"Записей истории: {stats['history']}\n"
        f"Счётчиков лимита: {stats['usage']}\n"
        f"Записей кэша: {stats['cache']}\n"
        f"Наблюдений: {stats.get('watches', 0)}\n"
        f"Снимков наблюдений: {stats.get('snapshots', 0)}\n\n"
        "Кэш чужих запросов не затрагивается — удаляются только ваши данные.",
        link_preview_options=NO_PREVIEW,
    )


@router.message(Command("setkey"))
async def cmd_setkey(message: Message, command: CommandObject) -> None:
    if not await is_owner(message.from_user.id):
        await message.answer("Команда доступна только владельцу бота.")
        return

    args = (command.args or "").split(maxsplit=1)
    if not args:
        await message.answer(
            "Формат: <code>/setkey &lt;provider&gt; [api_key]</code>\n"
            f"Провайдеры: {', '.join(config_module.SUPPORTED_SEARCH_PROVIDERS)}\n"
            "Текущий: <code>{}</code>".format(app_cfg.search.provider),
            link_preview_options=NO_PREVIEW,
        )
        return

    provider = args[0].lower()
    if provider not in config_module.SUPPORTED_SEARCH_PROVIDERS:
        await message.answer(
            f"Неизвестный провайдер. Допустимо: {', '.join(config_module.SUPPORTED_SEARCH_PROVIDERS)}"
        )
        return

    app_cfg.search.provider = provider
    if len(args) > 1:
        app_cfg.search.api_key = args[1].strip()

    problems = config_module.validate_config(app_cfg)
    if problems:
        await message.answer("Не применил, есть проблемы:\n" + "\n".join(f"• {p}" for p in problems))
        return

    app_cfg.save()
    # Токен в ответе не показываем — только факт сохранения.
    await message.answer(
        f"✅ Провайдер поиска: <code>{provider}</code>. Настройки сохранены в config.yaml.",
        link_preview_options=NO_PREVIEW,
    )


@router.message(Command("evidence"))
async def cmd_evidence(message: Message, command: CommandObject) -> None:
    """
    Собирает доказательный пакет по реквизиту мошенничества.

    Принимает домен, адрес кошелька или название организации. Возвращает
    публичные регистрационные и технические данные — то, что принимают
    банк и полиция.
    """
    raw = (command.args or "").strip()
    if not raw:
        await message.answer(
            "📋 <b>Доказательный пакет</b>\n\n"
            "Формат: <code>/evidence &lt;домен | кошелёк | организация&gt;</code>\n\n"
            "Примеры:\n"
            "• <code>/evidence shady-shop.example</code> — домен мошенника\n"
            "• <code>/evidence 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</code> — BTC-кошелёк\n"
            "• <code>/evidence 0xd8dA6BF...96045</code> — ETH-адрес\n"
            "• <code>/evidence ООО Ромашка</code> — организация\n\n"
            "Собирается: регистратор домена, DNS, поддомены, хостинг, "
            "реестры юрлиц, санкции, публичная история блокчейна.",
            link_preview_options=NO_PREVIEW,
        )
        return

    subject = evidence_module.parse_evidence_input(raw)
    if subject is None:
        await message.answer(
            "Не удалось определить реквизит. Укажите домен, адрес кошелька "
            "или название организации (минимум 3 символа)."
        )
        return

    if not storage.try_consume_quota(
        message.from_user.id, app_cfg.limits.daily_requests_per_user
    ):
        await message.answer(
            f"⛔️ Дневной лимит исчерпан "
            f"({app_cfg.limits.daily_requests_per_user} запросов/сутки).\n"
            "Лимит обновится в 00:00 UTC.",
            link_preview_options=NO_PREVIEW,
        )
        return

    storage.history_add(message.from_user.id, f"evidence:{raw}")

    status = await message.answer(
        f"📋 Собираю доказательный пакет по <code>{raw}</code>…\n"
        f"{quota_note(message.from_user.id)}",
        link_preview_options=NO_PREVIEW,
    )

    try:
        pack = await evidence_module.build_pack(http_client, raw)
    except Exception as exc:  # noqa: BLE001 — бот не должен падать из-за источника
        log.exception("Сбор доказательного пакета упал")
        await status.edit_text(f"❌ Ошибка сбора: {type(exc).__name__}: {exc}")
        return

    _last_pack[message.from_user.id] = pack

    try:
        await status.delete()
    except Exception:  # noqa: BLE001 — сообщение могло быть уже удалено
        pass

    await send_long(message, evidence_module.build_pack_report(pack))


@router.message(Command("evidence_json"))
async def cmd_evidence_json(message: Message) -> None:
    """Отдаёт последний пакет в JSON — для приложения к заявлению."""
    pack = _last_pack.get(message.from_user.id)
    if pack is None:
        await message.answer(
            "Сначала соберите пакет: <code>/evidence &lt;домен или кошелёк&gt;</code>",
            link_preview_options=NO_PREVIEW,
        )
        return

    payload = pack.to_json()
    filename = f"evidence_{pack.subject.value[:40].replace('/', '_')}.json".replace(" ", "_")

    await message.answer_document(
        document=BufferedInputFile(payload.encode("utf-8"), filename=filename),
        caption=(
            f"📎 Доказательный пакет по <code>{pack.subject.value}</code>\n"
            f"Записей: {len(pack.findings)}. Только публичные данные."
        ),
    )


@router.message(Command("watch"))
async def cmd_watch(message: Message, command: CommandObject) -> None:
    """Ставит наблюдение за организацией или публичной фигурой."""
    raw = (command.args or "").strip()
    if not raw:
        await message.answer(
            "👀 <b>Наблюдение за публичными реестрами</b>\n\n"
            "Формат: <code>/watch &lt;название&gt;</code>\n"
            "Тип определяется автоматически, либо укажите явно:\n"
            "• <code>/watch ООО Ромашка</code>\n"
            "• <code>/watch person:Иван Иванов</code>\n"
            "• <code>/watch company:Acme Corp</code>\n\n"
            "Бот проверит официальные реестры (GLEIF, SEC EDGAR, OFAC SDN, Wikidata) "
            "и будет присылать только изменения.",
            link_preview_options=NO_PREVIEW,
        )
        return

    user_id = message.from_user.id
    existing = storage.watch_list(user_id)
    subject = monitor_module.clean_subject(raw)
    kind = monitor_module.detect_kind(raw)

    already = any(row["subject"] == subject for row in existing)
    if not already and len(existing) >= app_cfg.monitor.max_watches_per_user:
        await message.answer(
            f"Достигнут лимит наблюдений: {app_cfg.monitor.max_watches_per_user}.\n"
            "Удалите ненужные командой /unwatch.",
            link_preview_options=NO_PREVIEW,
        )
        return

    watch_id = storage.watch_add(user_id, subject, kind)

    status = await message.answer(
        f"👀 Ставлю наблюдение за <b>{subject}</b>…",
        link_preview_options=NO_PREVIEW,
    )

    # Первая проверка сразу: она создаёт базовый снимок для сравнения.
    row = next((r for r in storage.watch_all() if r["id"] == watch_id), None)
    if row is None:
        await status.edit_text("Не удалось создать наблюдение.")
        return

    check = await monitor_module.check_watch(storage, row, http_client)
    await status.edit_text(
        monitor_module.build_watch_report(check)
        + f"\n\nИнтервал проверки: {app_cfg.monitor.interval_hours} ч.",
        link_preview_options=NO_PREVIEW,
    )


@router.message(Command("watches"))
async def cmd_watches(message: Message) -> None:
    rows = storage.watch_list(message.from_user.id)
    await message.answer(
        monitor_module.build_watch_list(rows), link_preview_options=NO_PREVIEW
    )


@router.message(Command("unwatch"))
async def cmd_unwatch(message: Message, command: CommandObject) -> None:
    raw = (command.args or "").strip()
    if not raw:
        await message.answer("Формат: <code>/unwatch &lt;название&gt;</code>")
        return

    subject = monitor_module.clean_subject(raw)
    removed = storage.watch_remove(message.from_user.id, subject)
    if removed:
        await message.answer(f"🗑 Наблюдение за «{subject}» удалено вместе со снимками.")
    else:
        await message.answer(
            f"Наблюдение «{subject}» не найдено. Посмотреть список: /watches",
            link_preview_options=NO_PREVIEW,
        )


async def collect_footprint(nick: str, http: HttpClient, cfg: AppConfig) -> list:
    """
    Собирает публичный след по нику тем же конвейером, что и обычный поиск.

    Вынесено на уровень модуля: так не тянем глобальные зависимости во
    вложенную функцию и проще тестировать.
    """
    query = build_query(nick)
    ctx = SourceContext(
        http=http,
        search_provider=cfg.search.provider,
        search_api_key=cfg.search.api_key,
        github_token=cfg.github.token,
        max_results=cfg.limits.max_results_per_source,
    )
    outcome = await run_search(
        query,
        ctx,
        source_timeout=cfg.network.source_timeout,
        overall_timeout=cfg.network.source_timeout + 10,
    )
    # report.exact/likely хранят ScoredFinding — разворачиваем до Finding.
    return [scored.finding for scored in outcome.report.exact + outcome.report.likely]


@router.message(Command("mytrace"))
async def cmd_mytrace(message: Message, command: CommandObject) -> None:
    """
    Аудит собственного публичного следа.

    Работает по вашим данным: username, пароль, e-mail. Пароль проверяется
    через k-anonymity и наружу не уходит.
    """
    raw = (command.args or "").strip()
    if not raw:
        await message.answer(
            "🔐 <b>Аудит своего публичного следа</b>\n\n"
            "• <code>/mytrace &lt;username&gt;</code> — что видно по вашему нику\n"
            "• <code>/mytrace &lt;username&gt; --pw &lt;пароль&gt;</code> — плюс проверка пароля\n"
            "• <code>/mytrace --pw &lt;пароль&gt;</code> — только проверка пароля\n\n"
            "<i>Пароль не передаётся: наружу уходят только 5 символов SHA-1 хеша "
            "(k-anonymity), восстановить по ним пароль невозможно.</i>",
            link_preview_options=NO_PREVIEW,
        )
        return

    # Разбор аргументов: поддерживаем --pw <пароль> и --email <адрес>.
    password = ""
    email = ""
    parts = raw.split()
    username_parts: list[str] = []
    index = 0
    while index < len(parts):
        token = parts[index]
        if token == "--pw" and index + 1 < len(parts):
            password = parts[index + 1]
            index += 2
            continue
        if token == "--email" and index + 1 < len(parts):
            email = parts[index + 1]
            index += 2
            continue
        username_parts.append(token)
        index += 1

    username = normalize_username(username_parts[0]) if username_parts else ""

    if not username and not password:
        await message.answer(
            "Укажите username или пароль. Пример: "
            "<code>/mytrace my_nick --pw mypassword</code>",
            link_preview_options=NO_PREVIEW,
        )
        return

    status = await message.answer(
        "🔐 Проверяю ваш публичный след…", link_preview_options=NO_PREVIEW
    )

    # Сборщик следа подключаем только если задан username.
    # partial фиксирует зависимости сейчас — к этому моменту они уже созданы в main().
    collector = None
    if username:
        collector = partial(collect_footprint, http=http_client, cfg=app_cfg)

    try:
        result = await selftrace_module.run_selftrace(
            http_client,
            username=username,
            password=password,
            email=email,
            hibp_key=app_cfg.hibp.api_key,
            footprint_collector=collector,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("Самопроверка упала")
        await status.edit_text(f"❌ Ошибка: {type(exc).__name__}: {exc}")
        return

    try:
        await status.delete()
    except Exception:  # noqa: BLE001
        pass

    await send_long(message, selftrace_module.build_selftrace_report(result))


@router.message(Command("breaches"))
async def cmd_breaches(message: Message, command: CommandObject) -> None:
    """Публичный каталог крупных утечек, опционально с фильтром по слову."""
    keyword = (command.args or "").strip()
    status = await message.answer("🗂 Загружаю каталог утечек…", link_preview_options=NO_PREVIEW)

    try:
        findings = await breach_module.breach_catalog(http_client, keyword=keyword)
    except Exception as exc:  # noqa: BLE001
        await status.edit_text(f"❌ Не удалось загрузить каталог: {type(exc).__name__}: {exc}")
        return

    if not findings:
        await status.edit_text(
            "Ничего не найдено по этому фильтру." if keyword else "Каталог пуст."
        )
        return

    lines = ["🗂 <b>Крупные публичные утечки</b>", ""]
    if keyword:
        lines.append(f"Фильтр: <code>{keyword}</code>")
        lines.append("")
    for finding in findings:
        lines.append(f"• <b>{finding.title}</b>")
        lines.append(f"   {finding.snippet}")
        lines.append(f'   <a href="{finding.url}">подробнее</a>')
        lines.append("")
    lines.append(
        "<i>Каталог публичный и не содержит самих утёкших данных. "
        "Проверить свой пароль: /mytrace --pw &lt;пароль&gt;</i>"
    )

    await status.delete()
    await send_long(message, "\n".join(lines))


@router.message(F.text & ~F.text.startswith("/"))
async def on_text(message: Message) -> None:
    """Свободный текст: '@username' или 'username Имя Фамилия'."""
    text = (message.text or "").strip()
    if not text:
        return
    # Отсекаем явный мусор: одна строка, без переводов строк, разумной длины.
    if "\n" in text or len(text) > 120:
        await message.answer("Слишком длинный запрос. Пришлите один username или username + имя.")
        return
    if not normalize_username(text.split()[0]):
        await message.answer(
            "Это не похоже на username. Пример: <code>ivan_petrov</code> или "
            "<code>@ivan_petrov Иван Петров</code>",
            link_preview_options=NO_PREVIEW,
        )
        return
    await perform_search(message, text)


# --------------------------------------------------------------------------- #
# Запуск
# --------------------------------------------------------------------------- #
async def main() -> None:
    global storage, app_cfg, http_client

    app_cfg = config_module.ensure_config()

    storage = Storage(app_cfg.db_path_abs, cache_ttl_hours=app_cfg.limits.cache_ttl_hours)
    purged = storage.cache_purge_expired()
    if purged:
        log.info("Вычищено просроченных записей кэша: %s", purged)

    http_client = HttpClient(
        timeout=app_cfg.network.request_timeout,
        proxy_list=app_cfg.network.proxy_list,
        max_concurrency=app_cfg.network.max_concurrency,
    )

    bot = Bot(
        token=app_cfg.telegram.bot_token,
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )
    dp = Dispatcher()
    dp.include_router(router)

    try:
        # Проверяем токен сразу — понятная ошибка лучше трейсбека из глубины aiogram.
        try:
            me = await bot.get_me()
        except TelegramUnauthorizedError:
            raise SystemExit(
                "Telegram отклонил BOT_TOKEN (401 Unauthorized).\n"
                "Проверьте токен от @BotFather и запустите `python bot.py` снова."
            )
        except TelegramNetworkError as exc:
            raise SystemExit(
                f"Не удалось связаться с Telegram API: {exc}\n"
                "Проверьте сеть/прокси (network.proxy_list) и повторите запуск."
            )

        log.info("Бот запущен: @%s (id=%s)", me.username, me.id)
        log.info(
            "Провайдер поиска: %s | GitHub-токен: %s | прокси: %d | мониторинг: %s",
            app_cfg.search.provider,
            "есть" if app_cfg.github.token else "нет",
            len(app_cfg.network.proxy_list),
            f"каждые {app_cfg.monitor.interval_hours} ч" if app_cfg.monitor.enabled else "выключен",
        )

        # Фоновый обход наблюдений: отдельная задача, не блокирует polling.
        monitor_task: asyncio.Task | None = None
        if app_cfg.monitor.enabled:
            monitor_task = asyncio.create_task(
                monitor_module.monitor_loop(
                    storage,
                    http_client,
                    bot,
                    interval=app_cfg.monitor.interval_hours * 3600,
                )
            )

        try:
            # drop_pending_updates: не отвечаем на запросы, накопившиеся пока бот лежал.
            await dp.start_polling(bot, drop_pending_updates=True)
        finally:
            if monitor_task is not None:
                monitor_task.cancel()
                try:
                    await monitor_task
                except asyncio.CancelledError:
                    pass
                except Exception:  # noqa: BLE001 — падение фоновой задачи не должно мешать выходу
                    log.warning("Мониторинг завершился с ошибкой", exc_info=True)
    finally:
        await http_client.close()
        storage.close()
        await bot.session.close()
        log.info("Бот остановлен, ресурсы освобождены.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # SystemExit из config.ensure_config() пробрасываем как есть — сообщение
        # об ошибке конфигурации уже напечатано пользователю.
        print("\nБот остановлен пользователем (Ctrl+C).")
