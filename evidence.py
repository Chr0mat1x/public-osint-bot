"""
evidence.py — Scam Evidence Pack: доказательная папка по мошенничеству.

Назначение: жертва мошенничества отправляет боту реквизиты (домен, кошелёк,
название компании) и получает структурированный пакет с публичными данными,
который принимают банк и полиция.

Что собирается:
  * домен — кто зарегистрировал, когда, где хостится, какие поддомены;
  * юрлицо — реестр GLEIF, санкционный список OFAC, отчётность SEC;
  * криптоадрес — публичная история транзакций и связанные адреса;
  * архивные копии и сканы сайта — фиксация того, как сайт выглядел.

Чего здесь НЕТ и не будет:
  * персональных данных владельца (адрес, телефон, паспорт);
  * содержимого утечек;
  * любых сведений о людях, не причастных к схеме.

Пакет описывает СХЕМУ и РЕКВИЗИТЫ, а не человека. Именно в таком виде
материалы имеют доказательную силу.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from normalizer import Finding

from sources import crypto_public, domain_public, registries_public
from sources.http_client import HttpClient, HttpError

# Что пользователь передал на вход.
KIND_DOMAIN = "domain"
KIND_WALLET = "wallet"
KIND_COMPANY = "company"

# Верхняя граница, чтобы один запрос не превратился в сотню обращений.
MAX_FINDINGS = 60


@dataclass
class EvidenceInput:
    """Разобранный ввод: тип реквизита + нормализованное значение."""

    kind: str
    value: str
    raw: str = ""

    def label(self) -> str:
        return {
            KIND_DOMAIN: "домен",
            KIND_WALLET: "криптокошелёк",
            KIND_COMPANY: "организация",
        }.get(self.kind, self.kind)


def parse_evidence_input(text: str) -> Optional[EvidenceInput]:
    """
    Определяет тип реквизита по формату ввода.

    Порядок важен: сначала проверяем криптоадрес (у него строгий формат),
    потом домен/URL, иначе считаем это названием организации.
    """
    text = (text or "").strip()
    if not text:
        return None

    if crypto_public.detect_network(text):
        return EvidenceInput(kind=KIND_WALLET, value=text, raw=text)

    if domain_public.is_domain(text):
        return EvidenceInput(kind=KIND_DOMAIN, value=domain_public.normalize_domain(text), raw=text)

    # Название организации: минимум 3 символа, не одинокое слово из мусора.
    if len(text) >= 3:
        return EvidenceInput(kind=KIND_COMPANY, value=text, raw=text)

    return None


@dataclass
class EvidencePack:
    """Собранный пакет: вход, находки, заметки об ошибках источников."""

    subject: EvidenceInput
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    duration: float = 0.0
    created_at: float = field(default_factory=time.time)

    def by_kind(self, kind: str) -> List[Finding]:
        return [f for f in self.findings if f.kind == kind]

    def to_dict(self) -> Dict[str, Any]:
        """Сериализация для выгрузки в JSON."""
        return {
            "created_at": self.created_at,
            "subject": {"kind": self.subject.kind, "value": self.subject.value},
            "duration_seconds": round(self.duration, 2),
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


async def _collect_domain(http: HttpClient, domain: str, pack: EvidencePack) -> None:
    """Публичная инфраструктура домена."""
    steps = (
        ("RDAP", lambda: domain_public.rdap_lookup(http, domain)),
        ("DNS", lambda: domain_public.dns_records(http, domain)),
        ("Certificate Transparency", lambda: domain_public.crtsh_subdomains(http, domain)),
        ("urlscan.io", lambda: domain_public.urlscan_history(http, domain)),
        ("Wayback Machine", lambda: domain_public.wayback_snapshot(http, domain)),
    )
    for label, step in steps:
        try:
            pack.findings.extend(await step())
        except HttpError as exc:
            pack.notes.append(f"{label}: {exc}")

    # Геолокация хостинга — по IP из A-записи домена.
    try:
        dns = await http.get_json("https://dns.google/resolve", params={"name": domain, "type": "A"})
        for answer in (dns.get("Answer") or []):
            ip = str(answer.get("data") or "")
            if ip.count(".") == 3:
                try:
                    pack.findings.extend(await domain_public.hosting_geo(http, ip))
                except HttpError as exc:
                    pack.notes.append(f"Геолокация хостинга: {exc}")
                break
    except HttpError as exc:
        pack.notes.append(f"DNS A-запись: {exc}")


async def _collect_wallet(http: HttpClient, address: str, pack: EvidencePack) -> None:
    """Публичная история блокчейна."""
    try:
        pack.findings.extend(await crypto_public.collect(http, address))
    except (HttpError, ValueError) as exc:
        pack.notes.append(f"Блокчейн: {exc}")


async def _collect_company(http: HttpClient, name: str, pack: EvidencePack) -> None:
    """Официальные реестры по названию организации."""
    try:
        pack.findings.extend(await registries_public.gleif_search(http, name))
    except HttpError as exc:
        pack.notes.append(f"GLEIF: {exc}")

    try:
        pack.findings.extend(await registries_public.ofac_sanctions(http, name))
    except HttpError as exc:
        pack.notes.append(f"OFAC SDN: {exc}")

    try:
        pack.findings.extend(await registries_public.sec_filings(http, name))
    except HttpError as exc:
        pack.notes.append(f"SEC EDGAR: {exc}")


async def build_pack(http: HttpClient, text: str) -> EvidencePack:
    """
    Собирает доказательный пакет по реквизиту.

    Ошибка одного источника не отменяет пакет: причина попадает в notes,
    остальные данные всё равно собираются.
    """
    subject = parse_evidence_input(text)
    if subject is None:
        raise ValueError("Не удалось определить реквизит. Укажите домен, адрес кошелька или название организации.")

    pack = EvidencePack(subject=subject)
    started = time.time()

    if subject.kind == KIND_DOMAIN:
        await _collect_domain(http, subject.value, pack)
    elif subject.kind == KIND_WALLET:
        await _collect_wallet(http, subject.value, pack)
    else:
        await _collect_company(http, subject.value, pack)

    pack.findings = pack.findings[:MAX_FINDINGS]
    pack.duration = time.time() - started
    return pack


# --------------------------------------------------------------------------- #
# Отрисовка пакета для Telegram
# --------------------------------------------------------------------------- #
def _esc(value: str) -> str:
    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _short(value: str, limit: int = 220) -> str:
    value = " ".join(str(value or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _finding_line(index: int, finding: Finding) -> List[str]:
    lines = [f"{index}. <b>{_esc(finding.title or finding.url)}</b>"]
    if finding.url:
        lines.append(f'   🔗 <a href="{_esc(finding.url)}">{_esc(_short(finding.url, 90))}</a>')
    if finding.snippet:
        lines.append(f"   📝 {_esc(_short(finding.snippet))}")

    extra = finding.extra or {}
    # Показываем только значимые поля, без технического мусора.
    details = []
    for key, label in (
        ("registrar", "регистратор"),
        ("registered", "создан"),
        ("expires", "истекает"),
        ("nameservers", "NS"),
        ("chain", "сеть"),
        ("address", "адрес"),
        ("transactions", "транзакций"),
        ("received_btc", "получено BTC"),
        ("balance_btc", "баланс BTC"),
        ("balance_eth", "баланс ETH"),
        ("balance_trx", "баланс TRX"),
        ("lei", "LEI"),
        ("programs", "санкции"),
        ("isp", "провайдер"),
        ("country", "страна сервера"),
        ("snapshot_date", "снимок"),
    ):
        if extra.get(key):
            details.append(f"{label}: {_short(str(extra[key]), 80)}")

    if details:
        lines.append("   📎 " + "; ".join(details))
    lines.append("")
    return lines


SECTION_TITLES = {
    "domain": "🌐 Домен и инфраструктура",
    "dns": "📡 DNS-записи",
    "subdomain": "🔗 Поддомены",
    "scan": "🔍 Публичные сканы",
    "archive": "🗄 Архивные копии",
    "hosting": "🖥 Хостинг",
    "wallet": "💰 Кошелёк",
    "wallet_peer": "🔀 Связанные адреса",
    "token_balance": "🪙 Токены на адресе",
    "company": "🏢 Организация",
    "filing": "📄 Отчётность SEC",
    "person": "👤 Публичная фигура",
    "sanctions": "🚫 Санкционный список",
}

SECTION_ORDER = (
    "company",
    "sanctions",
    "filing",
    "person",
    "wallet",
    "token_balance",
    "wallet_peer",
    "domain",
    "dns",
    "subdomain",
    "hosting",
    "scan",
    "archive",
)


def build_pack_report(pack: EvidencePack) -> str:
    """Собирает текст доказательного пакета для отправки в Telegram."""
    subject = pack.subject
    lines = [
        "📋 <b>Доказательный пакет</b>",
        "",
        f"🎯 Реквизит ({_esc(subject.label())}): <code>{_esc(subject.value)}</code>",
        f"📈 Найдено записей: {len(pack.findings)}",
        f"⏱ {pack.duration:.1f} с",
        "",
    ]

    if not pack.findings:
        lines.append("❌ Публичных данных по этому реквизиту не найдено.\n")

    index = 0
    for kind in SECTION_ORDER:
        items = pack.by_kind(kind)
        if not items:
            continue
        lines.append(f"<b>{SECTION_TITLES.get(kind, kind)}</b>")
        lines.append("")
        for finding in items:
            index += 1
            lines.extend(_finding_line(index, finding))

    if pack.notes:
        lines.append("⚠️ <b>Источники с ошибками</b>")
        lines.append("")
        for note in pack.notes[:10]:
            lines.append(f"• {_esc(_short(note, 140))}")
        lines.append("")

    lines.extend(
        [
            "📌 <b>Как использовать</b>",
            "",
            "1. Сохраните этот отчёт (перешлите себе или выгрузите /evidence_json).",
            "2. Приложите к заявлению: переписку, чеки, реквизиты перевода.",
            "3. Банк — заявление о возврате (чарджбэк), полиция — заявление о мошенничестве.",
            "4. Для домена укажите регистратору жалобу на abuse-адрес.",
            "",
            "<i>Пакет содержит только публичные регистрационные и технические данные "
            "о реквизитах схемы. Персональные данные владельца здесь отсутствуют — "
            "их запрашивает следствие официальным путём.</i>",
        ]
    )

    return "\n".join(lines).strip()
