"""
sources/registries_public.py — официальные публичные реестры.

Только официальные государственные и международные реестры, публикуемые
для открытого доступа:

  * GLEIF        — глобальный реестр юридических лиц (LEI), без ключа;
  * SEC EDGAR    — full-text поиск по отчётности публичных компаний США;
  * Wikidata     — структурированные публичные данные о публичных фигурах;
  * OFAC SDN     — официальный санкционный список США (публичный CSV).

Никаких слитых баз. Всё это данные, которые государства и реестры публикуют
сами — для проверки контрагентов, комплаенса и журналистики.
"""

from __future__ import annotations

import csv
import io
import re
import time
from typing import Any, Dict, List

from normalizer import Finding

from .http_client import HttpClient

UA = "osint-bot/1.0 (public-registry research)"
SEC_UA = "osint-bot/1.0 public-registry research"

# Ограничения выдачи, чтобы отчёт оставался читаемым.
MAX_COMPANIES = 8
MAX_FILINGS = 10
MAX_PERSONS = 5
MAX_SANCTIONS = 10

GLEIF_API = "https://api.gleif.org/api/v1/lei-records"
SEC_FTS = "https://efts.sec.gov/LATEST/search-index"
WIKIDATA_SPARQL = "https://query.wikidata.org/sparql"
OFAC_SDN = "https://www.treasury.gov/ofac/downloads/sdn.csv"

# Q5 в Wikidata — класс «человек». Фильтр нужен, чтобы вместо людей
# не прилетали события, интервью и новостные статьи с тем же названием.
WIKIDATA_HUMAN = "Q5"

# Санкционный список — большой файл, кэшируем в процессе на 6 часов.
_sdn_cache: Dict[str, Any] = {"ts": 0.0, "rows": []}
SDN_TTL_SECONDS = 6 * 3600


# --------------------------------------------------------------------------- #
# GLEIF — реестр юридических лиц
# --------------------------------------------------------------------------- #
async def gleif_search(http: HttpClient, name: str) -> List[Finding]:
    """Ищет юрлицо в глобальном реестре LEI по названию."""
    data = await http.get_json(
        GLEIF_API,
        params={"filter[entity.legalName]": name, "page[size]": MAX_COMPANIES},
        headers={"Accept": "application/vnd.api+json"},
    )

    findings: List[Finding] = []
    for record in (data.get("data") or [])[:MAX_COMPANIES]:
        attrs = record.get("attributes") or {}
        entity = attrs.get("entity") or {}
        legal_name = (entity.get("legalName") or {}).get("name") or ""
        address = entity.get("legalAddress") or {}
        registration = attrs.get("registration") or {}

        # Регистрационный адрес — официальные данные реестра, публикуемые для
        # того, чтобы контрагенты могли направлять юридически значимые сообщения.
        addr_parts = list(address.get("addressLines") or [])
        for key in ("city", "region", "postalCode", "country"):
            if address.get(key):
                addr_parts.append(str(address[key]))

        findings.append(
            Finding(
                source="registries_public",
                kind="company",
                url=f"https://search.gleif.org/#/record/{attrs.get('lei', '')}",
                title=legal_name or name,
                snippet="Юридическое лицо в реестре GLEIF (LEI).",
                display_name=legal_name,
                extra={
                    "registry": "GLEIF",
                    "lei": attrs.get("lei", ""),
                    "status": entity.get("status", ""),
                    "legal_form": (entity.get("legalForm") or {}).get("id", ""),
                    "registration_status": registration.get("status", ""),
                    "registered_address": ", ".join(p for p in addr_parts if p),
                    "creation_date": entity.get("creationDate", ""),
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# SEC EDGAR — отчётность публичных компаний США
# --------------------------------------------------------------------------- #
async def sec_filings(http: HttpClient, name: str) -> List[Finding]:
    """Full-text поиск по документам SEC EDGAR (публичная отчётность компаний)."""
    data = await http.get_json(
        SEC_FTS,
        params={"q": f'"{name}"', "forms": "10-K,10-Q,8-K"},
        headers={"User-Agent": SEC_UA},
    )

    findings: List[Finding] = []
    for hit in ((data.get("hits") or {}).get("hits") or [])[:MAX_FILINGS]:
        src = hit.get("_source") or {}
        display_names = src.get("display_names") or []
        company = display_names[0].split("  (")[0] if display_names else name
        ciks = src.get("ciks") or []
        accession = (src.get("adsh") or "").replace("-", "")
        doc_id = hit.get("_id") or ""
        filename = doc_id.split(":")[-1] if ":" in doc_id else ""

        # Ссылка на первоисточник в архиве EDGAR.
        if ciks and accession and filename:
            url = f"https://www.sec.gov/Archives/edgar/data/{int(ciks[0])}/{accession}/{filename}"
        else:
            url = f"https://efts.sec.gov/LATEST/search-index?q=%22{name}%22"

        findings.append(
            Finding(
                source="registries_public",
                kind="filing",
                url=url,
                title=f"{src.get('file_type') or 'документ'} — {company}",
                snippet=f"Дата подачи: {src.get('file_date') or '—'}. Компания из отчётности SEC.",
                display_name=company,
                extra={
                    "registry": "SEC EDGAR",
                    "form": src.get("file_type", ""),
                    "filed": src.get("file_date", ""),
                    "cik": ciks[0] if ciks else "",
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# Wikidata — публичные фигуры
# --------------------------------------------------------------------------- #
def _sparql_escape(value: str) -> str:
    """
    Экранирует пользовательский ввод для подстановки в SPARQL-строку.
    Убираем кавычки и обратные слэши, чтобы нельзя было вырваться из литерала.
    """
    return re.sub(r'["\\\n\r]', " ", value or "").strip()[:120]


async def wikidata_person(http: HttpClient, name: str) -> List[Finding]:
    """
    Ищет публичную фигуру в Wikidata через SPARQL.

    Фильтр `wdt:P31 wd:Q5` оставляет только людей — без него в выдачу
    попадают события, интервью и статьи с похожим названием.

    Данные Wikidata описывают публичную роль человека (политик, основатель
    компании, спортсмен) и не содержат приватных сведений.
    """
    safe_name = _sparql_escape(name)
    if len(safe_name) < 2:
        return []

    query = (
        "SELECT ?item ?itemLabel ?itemDescription WHERE { "
        f'?item wdt:P31 wd:{WIKIDATA_HUMAN}; rdfs:label "{safe_name}"@en. '
        'SERVICE wikibase:label { bd:serviceParam wikibase:language "en,ru". } '
        f"}} LIMIT {MAX_PERSONS}"
    )

    data = await http.get_json(
        WIKIDATA_SPARQL,
        params={"format": "json", "query": query},
        headers={"User-Agent": UA, "Accept": "application/sparql-results+json"},
    )

    findings: List[Finding] = []
    for binding in ((data.get("results") or {}).get("bindings") or [])[:MAX_PERSONS]:
        url = (binding.get("item") or {}).get("value") or ""
        label = (binding.get("itemLabel") or {}).get("value") or name
        description = (binding.get("itemDescription") or {}).get("value") or ""

        findings.append(
            Finding(
                source="registries_public",
                kind="person",
                url=url,
                title=label,
                snippet=description or "Публичная фигура в Wikidata.",
                display_name=label,
                extra={
                    "registry": "Wikidata",
                    "qid": url.rsplit("/", 1)[-1],
                    "role": description,
                },
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# OFAC SDN — санкционный список США
# --------------------------------------------------------------------------- #
async def _load_sdn(http: HttpClient) -> List[List[str]]:
    """Загружает и кэширует публичный санкционный список OFAC SDN."""
    now = time.time()
    if _sdn_cache["rows"] and now - _sdn_cache["ts"] < SDN_TTL_SECONDS:
        return _sdn_cache["rows"]

    text = await http.get_text(OFAC_SDN, headers={"User-Agent": UA})
    rows: List[List[str]] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) >= 4:
            rows.append(row)

    _sdn_cache["rows"] = rows
    _sdn_cache["ts"] = now
    return rows


def _clean_sdn(value: str) -> str:
    """OFAC использует '-0- ' как плейсхолдер «нет данных» — убираем его."""
    value = (value or "").strip()
    return "" if value in ("-0-", "-0- ") else value


def _parse_programs(value: str) -> List[str]:
    """
    Разбирает поле программ санкций.

    В файле OFAC программы записаны в скобках: "[FTO] [SDGT] [IRGC]".
    Для части записей скобки обрезаны ("FTO] [SDGT] [IRGC"), поэтому просто
    убираем все скобки и разбиваем по пробелам.
    """
    cleaned = _clean_sdn(value).replace("[", " ").replace("]", " ")
    return [p for p in cleaned.split() if p]


async def ofac_sanctions(http: HttpClient, name: str) -> List[Finding]:
    """
    Ищет имя в официальном санкционном списке OFAC SDN.

    Это публичный список, который OFAC публикует именно для того, чтобы
    компании могли проверять контрагентов перед сделкой.
    """
    needle = name.strip().lower()
    if len(needle) < 3:
        return []

    rows = await _load_sdn(http)

    findings: List[Finding] = []
    for row in rows:
        sdn_name = (row[1] or "").strip()
        if needle not in sdn_name.lower():
            continue

        programs = _parse_programs(row[3])
        remarks = _clean_sdn(row[11]) if len(row) > 11 else ""

        # Из remarks вытаскиваем альтернативные имена (a.k.a.) — полезно для
        # проверки, что найден именно нужный человек, а не однофамилец.
        aliases = re.findall(r"a\.k\.a\.\s*'([^']+)'", remarks)[:8]

        findings.append(
            Finding(
                source="registries_public",
                kind="sanctions",
                url="https://sanctionssearch.ofac.treas.gov/",
                title=sdn_name,
                snippet=(
                    f"Санкционная программа: {', '.join(programs) or '—'}."
                    + (f" Известные имена: {', '.join(aliases[:3])}." if aliases else "")
                ),
                display_name=sdn_name,
                extra={
                    "registry": "OFAC SDN",
                    "sdn_type": _clean_sdn(row[2]),
                    "programs": ", ".join(programs),
                    "aliases": ", ".join(aliases),
                    "remarks": remarks[:200],
                },
            )
        )
        if len(findings) >= MAX_SANCTIONS:
            break

    return findings


async def collect_all(http: HttpClient, name: str) -> List[Finding]:
    """
    Опрашивает все реестры параллельно. Ошибка одного не мешает остальным,
    причины собираются в список заметок (возвращается вторым элементом).
    """
    import asyncio

    tasks = {
        "GLEIF": gleif_search(http, name),
        "SEC EDGAR": sec_filings(http, name),
        "Wikidata": wikidata_person(http, name),
        "OFAC SDN": ofac_sanctions(http, name),
    }

    findings: List[Finding] = []
    notes: List[str] = []

    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for label, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            notes.append(f"{label}: {result}")
        else:
            findings.extend(result)

    return findings
