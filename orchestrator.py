"""
orchestrator.py — параллельный опрос источников, нормализация, дедупликация, скоринг.

Поток обработки запроса:
  Query → [4 источника параллельно, у каждого свой таймаут]
        → SourceResult'ы (успех / пропуск с причиной / ошибка)
        → merge всех находок → канонизация URL → дедупликация
        → фильтр по username → scorer → ScoredReport

Изоляция ошибок: падение или таймаут одного источника не влияет на остальные —
он просто попадает в отчёт со статусом «пропущен» и причиной (капча, 403, таймаут).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from normalizer import Finding, Query, SourceResult, deduplicate, filter_by_query
from scorer import ScoredReport, score_findings

from sources import SourceContext, get_collectors


@dataclass
class SearchOutcome:
    """Итог одного поиска: отчёт + статусы источников + метаданные."""

    query: Query
    report: ScoredReport
    sources: List[SourceResult] = field(default_factory=list)
    duration: float = 0.0
    cached: bool = False

    @property
    def total_findings(self) -> int:
        return self.report.total

    def source_status_lines(self) -> List[Tuple[str, str]]:
        """Строки вида (имя источника, статус) для отчёта."""
        lines: List[Tuple[str, str]] = []
        for res in self.sources:
            if not res.ok:
                lines.append((res.source, f"ошибка: {res.error}"))
            elif res.skipped:
                lines.append((res.source, f"пропущен: {res.error or 'нет данных'}"))
            else:
                lines.append((res.source, f"ок, находок: {len(res.findings)}"))
        return lines


async def _run_source(
    name: str,
    collector,
    query: Query,
    ctx: SourceContext,
    timeout: float,
) -> SourceResult:
    """Запускает один источник с жёстким таймаутом и полной изоляцией ошибок."""
    started = time.perf_counter()
    try:
        result = await asyncio.wait_for(collector(query, ctx), timeout=timeout)
        if not isinstance(result, SourceResult):
            result = SourceResult.failure(name, "источник вернул неожиданный тип данных")
        return result
    except asyncio.TimeoutError:
        return SourceResult.failure(name, f"таймаут источника ({timeout:.0f} с)")
    except asyncio.CancelledError:
        # Отмена всего поиска — пробрасываем наверх, это не ошибка источника.
        raise
    except Exception as exc:  # noqa: BLE001 — источник не должен ронять бота
        elapsed = time.perf_counter() - started
        return SourceResult.failure(name, f"{exc.__class__.__name__}: {exc} (за {elapsed:.1f} с)")


async def run_search(
    query: Query,
    ctx: SourceContext,
    *,
    source_timeout: float = 25.0,
    overall_timeout: Optional[float] = None,
) -> SearchOutcome:
    """Основная точка входа: параллельный опрос → нормализация → скоринг."""
    started = time.perf_counter()
    collectors = get_collectors()

    tasks = [
        asyncio.create_task(_run_source(name, collector, query, ctx, source_timeout))
        for name, collector in collectors
    ]

    try:
        if overall_timeout:
            results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=overall_timeout)
        else:
            results = await asyncio.gather(*tasks)
    except asyncio.TimeoutError:
        # Общий таймаут: забираем то, что успело завершиться, остальное отменяем.
        results = []
        for task, (name, _) in zip(tasks, collectors):
            if task.done() and not task.cancelled() and task.exception() is None:
                results.append(task.result())
            else:
                task.cancel()
                results.append(SourceResult.failure(name, "не успел до общего таймаута"))
        await asyncio.gather(*tasks, return_exceptions=True)

    sources = list(results)

    # --- нормализация ---------------------------------------------------- #
    merged: List[Finding] = []
    for res in sources:
        merged.extend(res.findings)

    deduped = deduplicate(merged)
    matched = filter_by_query(deduped, query)

    # --- скоринг --------------------------------------------------------- #
    report = score_findings(matched, query)

    return SearchOutcome(
        query=query,
        report=report,
        sources=sources,
        duration=time.perf_counter() - started,
    )


def outcome_to_cache(outcome: SearchOutcome) -> dict:
    """Сериализует результат для кэша (JSON-совместимый dict)."""
    return {
        "duration": outcome.duration,
        "sources": [
            {"source": r.source, "ok": r.ok, "skipped": r.skipped, "error": r.error}
            for r in outcome.sources
        ],
        "findings": [
            {
                "score": s.score,
                "bucket": s.bucket,
                "reasons": s.reasons,
                **s.finding.to_dict(),
            }
            for s in outcome.report.all_scored()
        ],
    }


def outcome_from_cache(query: Query, payload: dict, sources_map: Optional[dict] = None) -> SearchOutcome:
    """
    Восстанавливает SearchOutcome из кэша. Статусы источников берём из payload,
    поэтому отчёт после кэш-хита выглядит так же, как при живом поиске.
    """
    sources = [
        SourceResult(
            source=item.get("source", "unknown"),
            ok=bool(item.get("ok", True)),
            skipped=bool(item.get("skipped", False)),
            error=item.get("error"),
        )
        for item in payload.get("sources", [])
    ]

    findings = [Finding(**{k: v for k, v in item.items() if k not in ("score", "bucket", "reasons")})
                for item in payload.get("findings", [])]
    report = score_findings(findings, query)

    return SearchOutcome(
        query=query,
        report=report,
        sources=sources,
        duration=float(payload.get("duration", 0.0)),
        cached=True,
    )
