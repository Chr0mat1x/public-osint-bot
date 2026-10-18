"""
sources/crypto_public.py — публичные данные блокчейна.

Блокчейн по определению публичен: любая транзакция видна всем. Модуль
показывает активность адреса и связанные с ним адреса-контрагенты.

Поддерживаемые сети (все через публичные API без ключа):
  * Bitcoin  — blockchain.info;
  * Ethereum — Blockscout;
  * TRON     — Tronscan.

Зачем это нужно: при мошенничестве жертва почти всегда переводит средства на
криптоадрес. Публичная история переводов и связанные адреса — это то, что
принимает полиция и что биржи используют для блокировки вывода.

Модуль НЕ деанонимизирует владельца адреса: он показывает только то, что
и так записано в публичном реестре блокчейна.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from normalizer import Finding

from .http_client import HttpClient

BTC_API = "https://blockchain.info/rawaddr/{address}"
ETH_API = "https://eth.blockscout.com/api/v2/addresses/{address}"
TRON_API = "https://apilist.tronscanapi.com/api/account"

# Адреса в разных сетях различаются форматом.
BTC_RE = re.compile(r"^(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")
ETH_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
TRON_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")

MAX_COUNTERPARTIES = 10


def detect_network(address: str) -> Optional[str]:
    """Определяет сеть по формату адреса. None — не распознали."""
    address = (address or "").strip()
    if ETH_RE.match(address):
        return "ethereum"
    if TRON_RE.match(address):
        return "tron"
    if BTC_RE.match(address):
        return "bitcoin"
    return None


def _satoshi_to_btc(value: Any) -> str:
    try:
        return f"{int(value) / 100_000_000:.8f}".rstrip("0").rstrip(".") or "0"
    except (TypeError, ValueError):
        return "—"


async def bitcoin_lookup(http: HttpClient, address: str) -> List[Finding]:
    data: Dict[str, Any] = await http.get_json(BTC_API.format(address=address))

    findings = [
        Finding(
            source="crypto_public",
            kind="wallet",
            url=f"https://www.blockchain.com/explorer/addresses/btc/{address}",
            title=f"BTC-кошелёк {address[:14]}…",
            snippet=(
                f"Транзакций: {data.get('n_tx', 0)}, "
                f"получено: {_satoshi_to_btc(data.get('total_received'))} BTC, "
                f"баланс: {_satoshi_to_btc(data.get('final_balance'))} BTC."
            ),
            extra={
                "chain": "bitcoin",
                "address": address,
                "transactions": data.get("n_tx", 0),
                "received_btc": _satoshi_to_btc(data.get("total_received")),
                "balance_btc": _satoshi_to_btc(data.get("final_balance")),
            },
        )
    ]

    # Контрагенты: адреса, с которыми кошелёк обменивался средствами.
    counterparties: Dict[str, int] = {}
    for tx in (data.get("txs") or [])[:40]:
        for io_item in (tx.get("inputs") or []) + (tx.get("out") or []):
            peer = ((io_item.get("prev_out") or {}).get("addr") or io_item.get("addr") or "")
            if peer and peer != address:
                counterparties[peer] = counterparties.get(peer, 0) + 1

    for peer, count in sorted(counterparties.items(), key=lambda kv: -kv[1])[:MAX_COUNTERPARTIES]:
        findings.append(
            Finding(
                source="crypto_public",
                kind="wallet_peer",
                url=f"https://www.blockchain.com/explorer/addresses/btc/{peer}",
                title=f"Связанный адрес {peer[:14]}…",
                snippet=f"{count} взаимодействий с исходным кошельком (публичные транзакции).",
                extra={"chain": "bitcoin", "address": peer, "interactions": count},
            )
        )
    return findings


async def ethereum_lookup(http: HttpClient, address: str) -> List[Finding]:
    data: Dict[str, Any] = await http.get_json(ETH_API.format(address=address))

    balance_wei = data.get("coin_balance") or 0
    try:
        balance_eth = f"{int(balance_wei) / 10**18:.6f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        balance_eth = "—"

    extra = {
        "chain": "ethereum",
        "address": address,
        "balance_eth": balance_eth or "0",
        "is_contract": data.get("is_contract", False),
    }
    # ENS-имя — публичная, добровольно указанная владельцем метка адреса.
    if data.get("ens_domain_name"):
        extra["ens"] = data["ens_domain_name"]
    # Публичные метки и флаг скама, если сервис их проставил.
    if data.get("public_tags"):
        extra["public_tags"] = ", ".join(
            str(t.get("display_name") or t.get("label") or "") for t in data["public_tags"]
        )[:200]
    if data.get("is_scam"):
        extra["is_scam"] = True

    title = f"ETH-адрес {address[:12]}…"
    if data.get("ens_domain_name"):
        title += f" ({data['ens_domain_name']})"

    snippet = f"Баланс: {balance_eth or '0'} ETH."
    if data.get("is_contract"):
        snippet += " Это смарт-контракт, а не обычный кошелёк."
    if data.get("is_scam"):
        snippet += " Сервис пометил адрес как скам."

    return [
        Finding(
            source="crypto_public",
            kind="wallet",
            url=f"https://eth.blockscout.com/address/{address}",
            title=title,
            snippet=snippet,
            extra=extra,
        )
    ]


async def tron_lookup(http: HttpClient, address: str) -> List[Finding]:
    data: Dict[str, Any] = await http.get_json(TRON_API, params={"address": address})

    balance_trx = data.get("balance") or 0
    try:
        balance = f"{int(balance_trx) / 1_000_000:.6f}".rstrip("0").rstrip(".")
    except (TypeError, ValueError):
        balance = "—"

    findings = [
        Finding(
            source="crypto_public",
            kind="wallet",
            url=f"https://tronscan.org/#/address/{address}",
            title=f"TRON-кошелёк {address[:12]}…",
            snippet=(
                f"Баланс: {balance or '0'} TRX, "
                f"транзакций: {data.get('transactions') or data.get('totalTransactionCount') or 0}."
            ),
            extra={
                "chain": "tron",
                "address": address,
                "balance_trx": balance or "0",
                "transactions": data.get("transactions") or 0,
            },
        )
    ]

    # TRC20-токены на адресе (USDT — самый частый инструмент мошенничества).
    for token in (data.get("trc20token_balances") or [])[:5]:
        findings.append(
            Finding(
                source="crypto_public",
                kind="token_balance",
                url=f"https://tronscan.org/#/address/{address}",
                title=f"Токен {token.get('tokenAbbr') or '—'} на адресе",
                snippet=f"Баланс токена: {token.get('balance') or 0} (минимальные единицы).",
                extra={"chain": "tron", "token": token.get("tokenAbbr") or ""},
            )
        )
    return findings


async def collect(http: HttpClient, address: str) -> List[Finding]:
    """Определяет сеть по адресу и возвращает публичные данные блокчейна."""
    network = detect_network(address)
    if network is None:
        raise ValueError("Не распознан формат адреса (поддерживаются BTC, ETH, TRON).")

    if network == "ethereum":
        return await ethereum_lookup(http, address)
    if network == "tron":
        return await tron_lookup(http, address)
    return await bitcoin_lookup(http, address)
