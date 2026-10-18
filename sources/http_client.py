"""
sources/http_client.py — общий асинхронный HTTP-клиент для всех источников.

Что делает:
  * единый таймаут на запрос (network.request_timeout);
  * ротация прокси из PROXY_LIST;
  * реалистичный User-Agent и заголовки, чтобы публичные страницы отдавались нормально;
  * классификация ошибок: таймаут, HTTP-ошибка, капча, блокировка, rate-limit.

Важно: клиент не решает капчи и не обходит авторизацию. При капче/403 источник
просто пропускается — это осознанное поведение, зашитое в orchestrator.
"""

from __future__ import annotations

import asyncio
import itertools
import random
from typing import Any, Dict, List, Optional

import aiohttp

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
    "Cache-Control": "no-cache",
}

# Маркеры капчи/блокировки в теле ответа или в статусе.
CAPTCHA_MARKERS = (
    "captcha", "recaptcha", "hcaptcha", "are you a robot",
    "unusual traffic", "verify you are human", "cf-challenge", "just a moment",
)


class HttpError(Exception):
    """Ошибка запроса с человекочитаемым описанием для отчёта."""

    def __init__(self, message: str, kind: str = "http", status: Optional[int] = None) -> None:
        super().__init__(message)
        self.kind = kind      # timeout | http | captcha | blocked | ratelimit | network
        self.status = status


class HttpClient:
    def __init__(
        self,
        timeout: float = 12.0,
        proxy_list: Optional[List[str]] = None,
        max_concurrency: int = 8,
    ) -> None:
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=min(timeout, 8.0))
        self.proxies = list(proxy_list or [])
        self._proxy_cycle = itertools.cycle(self.proxies) if self.proxies else None
        self._semaphore = asyncio.Semaphore(max(1, max_concurrency))
        self._session: Optional[aiohttp.ClientSession] = None
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # Жизненный цикл сессии
    # ------------------------------------------------------------------ #
    async def _get_session(self) -> aiohttp.ClientSession:
        # Ленивая инициализация: сессию нужно создавать внутри работающего loop.
        if self._session is None or self._session.closed:
            async with self._lock:
                if self._session is None or self._session.closed:
                    connector = aiohttp.TCPConnector(limit=32, ssl=False)
                    self._session = aiohttp.ClientSession(
                        timeout=self.timeout, headers=DEFAULT_HEADERS, connector=connector
                    )
        return self._session

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> "HttpClient":
        await self._get_session()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------ #
    # Прокси
    # ------------------------------------------------------------------ #
    def _next_proxy(self) -> Optional[str]:
        if not self._proxy_cycle:
            return None
        return next(self._proxy_cycle)

    # ------------------------------------------------------------------ #
    # Запросы
    # ------------------------------------------------------------------ #
    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        expect_json: bool = False,
        retries: int = 2,
    ) -> Any:
        """
        Выполняет запрос и возвращает текст или распарсенный JSON.

        Бросает HttpError с kind:
          timeout   — истёк таймаут;
          captcha   — сервис показал капчу/челлендж;
          blocked   — 403/451 и подобное;
          ratelimit — 429;
          http      — прочие HTTP-ошибки;
          network   — сбой соединения/DNS/прокси.
        """
        session = await self._get_session()
        last_error: Optional[HttpError] = None

        for attempt in range(retries + 1):
            proxy = self._next_proxy()
            try:
                async with self._semaphore:
                    async with session.request(
                        method,
                        url,
                        params=params,
                        headers=headers,
                        data=data,
                        json=json_body,
                        proxy=proxy,
                        allow_redirects=True,
                    ) as resp:
                        status = resp.status
                        text = await resp.text(errors="replace")

                        if status == 429:
                            raise HttpError("Источник вернул 429 (слишком много запросов).",
                                            kind="ratelimit", status=status)
                        if status in (401, 403, 451):
                            raise HttpError(f"Источник заблокировал запрос (HTTP {status}).",
                                            kind="blocked", status=status)
                        if status >= 500:
                            raise HttpError(f"Ошибка на стороне источника (HTTP {status}).",
                                            kind="http", status=status)
                        if status >= 400:
                            raise HttpError(f"HTTP {status} от источника.",
                                            kind="http", status=status)

                        lowered = text[:4000].lower()
                        if any(marker in lowered for marker in CAPTCHA_MARKERS):
                            raise HttpError("Источник показал капчу/проверку — пропускаем.",
                                            kind="captcha", status=status)

                        if expect_json:
                            try:
                                return await resp.json(content_type=None)
                            except Exception as exc:  # noqa: BLE001 — нужен общий перехват парсинга
                                raise HttpError(f"Некорректный JSON от источника: {exc}",
                                                kind="http", status=status) from exc
                        return text

            except asyncio.TimeoutError:
                last_error = HttpError("Таймаут запроса к источнику.", kind="timeout")
            except HttpError as exc:
                # Капчу и блокировку повторять бессмысленно — выходим сразу.
                if exc.kind in ("captcha", "blocked", "ratelimit"):
                    raise
                last_error = exc
            except aiohttp.ClientError as exc:
                last_error = HttpError(f"Сетевая ошибка: {exc.__class__.__name__}", kind="network")
            except Exception as exc:  # noqa: BLE001 — страховка от неожиданных ошибок
                last_error = HttpError(f"Неожиданная ошибка: {exc}", kind="network")

            # Экспоненциальная пауза с джиттером перед следующей попыткой.
            if attempt < retries:
                await asyncio.sleep((0.6 * (2 ** attempt)) + random.uniform(0, 0.4))

        raise last_error or HttpError("Запрос не удался.", kind="network")

    async def get_text(self, url: str, **kwargs: Any) -> str:
        return await self.request("GET", url, **kwargs)

    async def get_json(self, url: str, **kwargs: Any) -> Any:
        kwargs["expect_json"] = True
        return await self.request("GET", url, **kwargs)
