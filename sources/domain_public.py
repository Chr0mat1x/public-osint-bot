"""
sources/domain_public.py — публичная инфраструктура домена.

Источники (все публичные, без авторизации):
  * RDAP          — регистрационные данные домена (замена WHOIS);
  * DNS over HTTPS — A/MX/TXT/NS записи через dns.google;
  * crt.sh        — публичные сертификаты → поддомены (Certificate Transparency);
  * urlscan.io    — публичная история сканирований домена;
  * Wayback       — архивные снимки;
  * ip-api        — геолокация ХОСТИНГА IP (не адрес человека).

Модуль нужен для доказательной папки по мошенничеству: он показывает, кто
владеет доменом, где он хостится, какие поддомены за ним стоят и как давно
сайт существует. Всё это — публичные регистрационные и технические данные.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlsplit

from normalizer import Finding

from .http_client import HttpClient, HttpError

UA = "osint-bot/1.0 (public-infrastructure research)"

RDAP = "https://rdap.org/domain/{domain}"
DOH = "https://dns.google/resolve"
CRTSH = "https://crt.sh/"
CERTSPOTTER = "https://api.certspotter.com/v1/issuances"
URLSCAN = "https://urlscan.io/api/v1/search/"
WAYBACK = "https://archive.org/wayback/available"
IPAPI = "http://ip-api.com/json/{ip}"

MAX_SUBDOMAINS = 15
MAX_SCANS = 8
CERTSPOTTER_MAX_CERTS = 100

# Типы DNS-записей, которые показывают владельца и почтовую инфраструктуру.
DNS_TYPES = (("MX", 15), ("TXT", 16), ("NS", 2))


def normalize_domain(value: str) -> str:
    """Приводит ввод (URL или домен) к чистому домену нижнего регистра."""
    value = (value or "").strip()
    if not value:
        return ""
    if "://" in value:
        return urlsplit(value).netloc.lower().split(":")[0]
    return value.split("/")[0].lower().split(":")[0]


def is_domain(value: str) -> bool:
    domain = normalize_domain(value)
    return "." in domain and " " not in domain and len(domain) >= 4


# --------------------------------------------------------------------------- #
# RDAP
# --------------------------------------------------------------------------- #
async def rdap_lookup(http: HttpClient, domain: str) -> List[Finding]:
    """Регистрационные данные домена: даты, регистратор, статусы, NS."""
    data: Dict[str, Any] = await http.get_json(RDAP.format(domain=domain))

    events: Dict[str, str] = {}
    for event in data.get("events") or []:
        if event.get("eventAction") and event.get("eventDate"):
            events[str(event["eventAction"]).lower()] = str(event["eventDate"])[:10]

    registrar = ""
    for entity in data.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray") or []
            if len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        registrar = str(field[3])
                        break
            if not registrar:
                registrar = str(entity.get("handle") or "")

    nameservers = [str(ns.get("ldhName") or "").lower() for ns in (data.get("nameservers") or [])]

    snippet_parts = []
    if events.get("registration"):
        snippet_parts.append(f"зарегистрирован {events['registration']}")
    if events.get("expiration"):
        snippet_parts.append(f"истекает {events['expiration']}")
    if registrar:
        snippet_parts.append(f"регистратор {registrar}")

    return [
        Finding(
            source="domain_public",
            kind="domain",
            url=f"https://{domain}",
            title=f"Домен {domain}",
            snippet="; ".join(snippet_parts) or "Регистрационные данные RDAP.",
            extra={
                "registry": "RDAP",
                "registered": events.get("registration", ""),
                "expires": events.get("expiration", ""),
                "updated": events.get("last changed", ""),
                "registrar": registrar,
                "status": ", ".join(data.get("status") or []),
                "nameservers": ", ".join(filter(None, nameservers)),
            },
        )
    ]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
async def dns_records(http: HttpClient, domain: str) -> List[Finding]:
    """Публичные DNS-записи домена: MX (почта), TXT (верификации), NS."""
    findings: List[Finding] = []

    for label, rtype in DNS_TYPES:
        try:
            data = await http.get_json(DOH, params={"name": domain, "type": label})
        except HttpError:
            continue

        records = [str(a.get("data") or "") for a in (data.get("Answer") or [])]
        if not records:
            continue

        findings.append(
            Finding(
                source="domain_public",
                kind="dns",
                url=f"https://dns.google/query?name={domain}&type={label}",
                title=f"DNS {label} — {domain}",
                snippet="; ".join(records[:6])[:300],
                extra={"registry": "DNS", "record_type": label, "records": records[:6]},
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# Certificate Transparency (crt.sh)
# --------------------------------------------------------------------------- #
def _clean_subdomain_names(raw_names: List[str], domain: str) -> List[str]:
    """
    Приводит имена из CT-логов к чистому списку поддоменов.

    Логи сертификатов содержат посторонние домены (например, для telegram.org
    встречается mail.telegram.supply) и wildcard-записи. Оставляем только
    имена, которые реально принадлежат запрошенному домену.
    """
    suffix = "." + domain
    names: List[str] = []

    for name in raw_names:
        name = str(name or "").strip().lower().lstrip("*.")
        if not name or name == domain:
            continue
        # Только поддомены запрошенного домена: отсекает mail.telegram.supply.
        if not name.endswith(suffix):
            continue
        if name not in names:
            names.append(name)

    return names


async def _certspotter_names(http: HttpClient, domain: str) -> List[str]:
    """Поддомены из certspotter (стабильнее crt.sh)."""
    data = await http.get_json(
        CERTSPOTTER,
        params={
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        headers={"User-Agent": UA},
    )

    raw: List[str] = []
    for entry in (data if isinstance(data, list) else [])[:CERTSPOTTER_MAX_CERTS]:
        raw.extend(entry.get("dns_names") or [])

    return _clean_subdomain_names(raw, domain)


async def _crtsh_names(http: HttpClient, domain: str) -> List[str]:
    """Поддомены из crt.sh — фолбэк, если certspotter недоступен."""
    data = await http.get_json(
        CRTSH, params={"q": f"%.{domain}", "output": "json"}, headers={"User-Agent": UA}
    )

    raw: List[str] = []
    for entry in data if isinstance(data, list) else []:
        raw.extend(str(entry.get("name_value") or "").split("\n"))

    return _clean_subdomain_names(raw, domain)


async def crtsh_subdomains(http: HttpClient, domain: str) -> List[Finding]:
    """
    Публичные поддомены из журналов Certificate Transparency.

    Сначала пробуем certspotter, при сбое — crt.sh. Оба сервиса периодически
    недоступны с датацентровых IP: тогда источник честно пропускается,
    а не выдаёт пустой результат.
    """
    try:
        names = await _certspotter_names(http, domain)
        registry = "certspotter"
    except (HttpError, ValueError):
        names = await _crtsh_names(http, domain)
        registry = "crt.sh"

    if not names:
        return []

    return [
        Finding(
            source="domain_public",
            kind="subdomain",
            url=f"https://{name}",
            title=name,
            snippet="Поддомен из публичного журнала Certificate Transparency.",
            extra={"registry": registry},
        )
        for name in names[:MAX_SUBDOMAINS]
    ]


# --------------------------------------------------------------------------- #
# urlscan.io
# --------------------------------------------------------------------------- #
async def urlscan_history(http: HttpClient, domain: str) -> List[Finding]:
    """
    Публичная история сканирований домена на urlscan.io.

    Полезно для доказательной папки: видно, как сайт выглядел в разные даты
    и на какие ресурсы он ссылался.
    """
    data: Dict[str, Any] = await http.get_json(
        URLSCAN, params={"q": f"domain:{domain}", "size": MAX_SCANS}
    )

    findings: List[Finding] = []
    for result in (data.get("results") or [])[:MAX_SCANS]:
        page = (result.get("page") or {})
        task = (result.get("task") or {})
        scan_id = result.get("_id") or ""
        url = page.get("url") or ""
        if not url:
            continue

        findings.append(
            Finding(
                source="domain_public",
                kind="scan",
                url=f"https://urlscan.io/result/{scan_id}/" if scan_id else url,
                title=f"Скан: {url[:100]}",
                snippet=f"Сканирован: {task.get('time') or '—'}. Публичный отчёт urlscan.io.",
                extra={
                    "registry": "urlscan.io",
                    "scanned_at": task.get("time") or "",
                    "target_url": url,
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Wayback
# --------------------------------------------------------------------------- #
async def wayback_snapshot(http: HttpClient, domain: str) -> List[Finding]:
    """Ближайший архивный снимок сайта — подтверждает, что и когда публиковалось."""
    data: Dict[str, Any] = await http.get_json(WAYBACK, params={"url": domain})

    closest = ((data.get("archived_snapshots") or {}).get("closest") or {})
    if not closest.get("available"):
        return []

    timestamp = str(closest.get("timestamp") or "")
    date = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}" if len(timestamp) >= 8 else timestamp

    return [
        Finding(
            source="domain_public",
            kind="archive",
            url=str(closest.get("url") or ""),
            title=f"Архивный снимок {domain}",
            snippet=f"Сохранённая копия сайта на {date or 'неизвестную дату'}.",
            extra={"registry": "Wayback Machine", "snapshot_date": date},
        )
    ]


# --------------------------------------------------------------------------- #
# IP-геолокация хостинга
# --------------------------------------------------------------------------- #
async def hosting_geo(http: HttpClient, ip: str) -> List[Finding]:
    """
    Геолокация ХОСТИНГА по IP.

    Это расположение сервера, а не адрес человека. Важно для доказательной
    папки: показывает, в какой юрисдикции находится сервер мошенника.
    """
    data: Dict[str, Any] = await http.get_json(IPAPI.format(ip=ip))
    if data.get("status") != "success":
        return []

    location = ", ".join(filter(None, [data.get("city"), data.get("regionName"), data.get("country")]))

    return [
        Finding(
            source="domain_public",
            kind="hosting",
            url=f"https://ip-api.com/#{ip}",
            title=f"Хостинг {ip}",
            snippet=f"Сервер расположен: {location or '—'}. Провайдер: {data.get('isp') or '—'}.",
            extra={
                "registry": "ip-api",
                "ip": ip,
                "country": data.get("country", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as": data.get("as", ""),
                "note": "геолокация сервера, не адрес человека",
            },
        )
    ]
