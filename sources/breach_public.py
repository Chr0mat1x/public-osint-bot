"""
sources/breach_public.py — проверка собственных данных в известных утечках.

Используется ТОЛЬКО в режиме самопроверки (/mytrace) и только по данным,
которые пользователь ввёл как свои.

Как это работает и почему это безопасно:

  * Пароли проверяются через HIBP Password k-anonymity API: клиент отправляет
    первые 5 символов SHA-1 хеша, сервер возвращает список суффиксов. Полный
    хеш и сам пароль наружу не уходят НИКОГДА.
  * E-mail проверяется через HIBP Breached Account API. Этот endpoint требует
    платный ключ; без ключа показываем каталог утечек (публичный, без ключа)
    и объясняем, как проверить себя.

Модуль НЕ отдаёт содержимое утечек: только факт «этот пароль встречался
в утечке N раз» и ссылку на смену пароля.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List

from normalizer import Finding

from .http_client import HttpClient, HttpError

UA = "osint-bot/1.0 (self-check)"

HIBP_RANGE = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_ACCOUNT = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


async def password_exposure(http: HttpClient, password: str) -> Finding:
    """
    Проверяет пароль через k-anonymity.

    Наружу уходят только первые 5 символов SHA-1 хеша — по ним невозможно
    восстановить пароль. Полный хеш сравнивается локально.
    """
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]

    body = await http.get_text(HIBP_RANGE.format(prefix=prefix), headers={"User-Agent": UA})

    count = 0
    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                count = int(parts[1])
            except ValueError:
                count = 0
            break

    return Finding(
        source="breach_public",
        kind="password_check",
        url="https://haveibeenpwned.com/Passwords",
        title="Пароль найден в утечках" if count else "Пароль в утечках не найден",
        snippet=(
            f"Этот пароль встречается в публичных утечках {count} раз. "
            "Смените его везде, где он использовался."
            if count
            else "Хороший знак: пароль не встречается в известных публичных утечках."
        ),
        extra={
            "registry": "HIBP k-anonymity",
            "occurrences": count,
            "note": "проверка выполнена без передачи пароля и полного хеша",
        },
    )


async def breach_catalog(http: HttpClient, keyword: str = "") -> List[Finding]:
    """Публичный каталог известных утечек (без ключа). Можно фильтровать по слову."""
    data: List[Dict[str, Any]] = await http.get_json(HIBP_BREACHES, headers={"User-Agent": UA})

    findings: List[Finding] = []
    keyword = (keyword or "").lower()

    for breach in data or []:
        name = str(breach.get("Name") or "")
        domain = str(breach.get("Domain") or "")
        title = str(breach.get("Title") or name)
        if keyword and keyword not in f"{name} {title} {domain}".lower():
            continue

        classes = ", ".join(breach.get("DataClasses") or [])
        findings.append(
            Finding(
                source="breach_public",
                kind="breach",
                url=f"https://haveibeenpwned.com/PwnedWebsites#{name}",
                title=title,
                snippet=(
                    f"Утечка {breach.get('BreachDate') or '—'}, "
                    f"затронуто {breach.get('PwnCount') or 0:,} аккаунтов. Данные: {classes}."
                ),
                extra={
                    "registry": "HIBP",
                    "breach_date": breach.get("BreachDate") or "",
                    "pwn_count": breach.get("PwnCount") or 0,
                    "data_classes": classes,
                    "domain": domain,
                },
            )
        )
        if len(findings) >= 15:
            break

    return findings


async def email_exposure(http: HttpClient, email: str, api_key: str = "") -> Finding:
    """
    Проверяет e-mail по HIBP Breached Account API.

    Без ключа API отвечает 401 — в этом случае честно сообщаем, что нужен
    ключ, и не притворяемся, что «утечек нет».
    """
    if not api_key:
        return Finding(
            source="breach_public",
            kind="email_check",
            url="https://haveibeenpwned.com/",
            title="Проверка e-mail требует ключа HIBP",
            snippet=(
                "Для проверки конкретного e-mail нужен платный ключ HIBP "
                "(hibp-api-key). Пароли проверяются без ключа — командой /mytrace."
            ),
            extra={"registry": "HIBP", "needs_key": True},
        )

    try:
        data = await http.get_json(
            HIBP_ACCOUNT.format(account=email),
            headers={"User-Agent": UA, "hibp-api-key": api_key},
        )
    except HttpError as exc:
        if exc.status == 404:
            return Finding(
                source="breach_public",
                kind="email_check",
                url="https://haveibeenpwned.com/",
                title="E-mail в утечках не найден",
                snippet="Этот адрес не встречается в известных публичных утечках HIBP.",
                extra={"registry": "HIBP", "breaches": 0},
            )
        raise

    names = [str(b.get("Name") or "") for b in (data or [])]
    return Finding(
        source="breach_public",
        kind="email_check",
        url="https://haveibeenpwned.com/",
        title=f"E-mail найден в утечках: {len(names)}",
        snippet="Утечки: " + ", ".join(names[:10]) + ". Смените пароли на этих сервисах.",
        extra={"registry": "HIBP", "breaches": len(names), "names": names[:10]},
    )
