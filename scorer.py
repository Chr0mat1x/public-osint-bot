"""
scorer.py — оценка совпадений и разметка «точно / вероятно».

Идея: у каждой находки считаем confidence в диапазоне 0..1 по прозрачным
правилам. Затем раскладываем по трём корзинам:

  exact   (точно)     — уверенно тот же человек: совпал username в URL/логине.
  likely  (вероятно)  — сильные косвенные признаки: совпало имя + контекст.
  unclear (неясно)    — слабое упоминание, может быть однофамильцем.

Веса подобраны эвристически и намеренно задокументированы, чтобы результат
был объяснимым: в отчёте рядом с каждой находкой видно, почему она попала
в ту или иную корзину.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from normalizer import Finding, Query, url_host, username_from_profile_url

# Порог для «точно» и «вероятно».
EXACT_THRESHOLD = 0.75
LIKELY_THRESHOLD = 0.45

# Платформы, где username из URL — надёжный идентификатор (логины уникальны).
HIGH_TRUST_HOSTS = {
    "github.com", "t.me", "reddit.com", "www.reddit.com", "stackoverflow.com",
    "habr.com", "last.fm", "www.last.fm", "soundcloud.com", "twitch.tv",
    "news.ycombinator.com", "medium.com", "www.medium.com",
}

# Домены, которые почти всегда не несут полезного сигнала о человеке.
NOISE_HOSTS = {
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "x.com", "twitter.com", "linkedin.com", "www.linkedin.com",
    "youtube.com", "www.youtube.com", "tiktok.com", "www.tiktok.com",
}


@dataclass
class ScoredFinding:
    finding: Finding
    score: float
    bucket: str                       # exact | likely | unclear
    reasons: List[str] = field(default_factory=list)


@dataclass
class ScoredReport:
    query: Query
    exact: List[ScoredFinding] = field(default_factory=list)
    likely: List[ScoredFinding] = field(default_factory=list)
    unclear: List[ScoredFinding] = field(default_factory=list)
    profile_links: List[Tuple[str, str]] = field(default_factory=list)   # (платформа, url)

    @property
    def total(self) -> int:
        return len(self.exact) + len(self.likely) + len(self.unclear)

    def all_scored(self) -> List[ScoredFinding]:
        return self.exact + self.likely + self.unclear


def _token_match(text: str, needle: str) -> bool:
    if not text or not needle:
        return False
    pattern = rf"(?<![a-z0-9._-]){re.escape(needle.lower())}(?![a-z0-9._-])"
    return re.search(pattern, text.lower()) is not None


def score_finding(finding: Finding, query: Query) -> ScoredFinding:
    """Считает confidence для одной находки и объясняет оценку."""
    score = 0.0
    reasons: List[str] = []

    host = url_host(finding.url)
    url_username = username_from_profile_url(finding.url)
    target_user = (query.username or "").lower()
    target_name = (query.full_name or "").lower()

    # 1. Совпадение username в URL/логине — самый сильный признак.
    if target_user and url_username and url_username == target_user:
        score += 0.55
        reasons.append(f"username совпал в URL профиля ({host or 'сайт'})")
    elif target_user and url_username and target_user in url_username:
        score += 0.25
        reasons.append("username частично совпал в URL")

    # 2. Совпадение username в логине/отображаемом имени находки.
    if target_user and finding.username and finding.username.lower() == target_user:
        score += 0.35
        reasons.append("логин профиля совпадает точно")
    elif target_user and _token_match(finding.display_name, target_user):
        score += 0.2
        reasons.append("username найден в публичном имени")

    # 3. Совпадение полного имени.
    if target_name and _token_match(finding.display_name or finding.title, target_name):
        score += 0.25
        reasons.append("публичное имя совпало")
    elif target_name and _token_match(finding.snippet, target_name):
        score += 0.1
        reasons.append("имя упомянуто в описании")

    # 4. Упоминание username в тексте (заголовок/сниппет) — слабый, но полезный сигнал.
    if target_user and (_token_match(finding.title, target_user) or _token_match(finding.snippet, target_user)):
        score += 0.15
        reasons.append("username встречается в тексте")

    # 5. Доверие к платформе.
    if host in HIGH_TRUST_HOSTS:
        score += 0.1
        reasons.append("уникальные логины на платформе")
    elif host in NOISE_HOSTS:
        score -= 0.1
        reasons.append("соцсеть с массовыми однофамильцами — понижен вес")

    # 6. Профиль надёжнее поста/репозитория.
    if finding.kind == "profile":
        score += 0.05
    elif finding.kind == "repo":
        score += 0.02

    score = max(0.0, min(1.0, round(score, 3)))

    if score >= EXACT_THRESHOLD:
        bucket = "exact"
    elif score >= LIKELY_THRESHOLD:
        bucket = "likely"
    else:
        bucket = "unclear"

    if not reasons:
        reasons.append("слабые/косвенные признаки совпадения")

    return ScoredFinding(finding=finding, score=score, bucket=bucket, reasons=reasons)


def score_findings(findings: Iterable[Finding], query: Query) -> ScoredReport:
    """Скорит весь список находок и раскладывает по корзинам."""
    report = ScoredReport(query=query)

    for finding in findings:
        scored = score_finding(finding, query)
        if scored.bucket == "exact":
            report.exact.append(scored)
        elif scored.bucket == "likely":
            report.likely.append(scored)
        else:
            report.unclear.append(scored)

    for bucket in (report.exact, report.likely, report.unclear):
        bucket.sort(key=lambda s: s.score, reverse=True)

    report.profile_links = _collect_profile_links(report)
    return report


def _collect_profile_links(report: ScoredReport) -> List[Tuple[str, str]]:
    """Собирает уникальные ссылки на публичные профили для сводки в шапке отчёта."""
    seen: Dict[str, str] = {}
    for scored in report.all_scored():
        finding = scored.finding
        if finding.kind != "profile" or not finding.url:
            continue
        platform = url_host(finding.url) or finding.source
        seen.setdefault(platform, finding.url)
    return sorted(seen.items(), key=lambda item: item[0])


def confidence_label(bucket: str) -> str:
    """Человекочитаемая метка уверенности для отчёта."""
    return {"exact": "точно", "likely": "вероятно", "unclear": "неясно"}.get(bucket, "неясно")


def summarize_confidence(report: ScoredReport) -> str:
    """Короткая строка-сводка: сколько находок в каждой корзине."""
    parts = []
    if report.exact:
        parts.append(f"точно: {len(report.exact)}")
    if report.likely:
        parts.append(f"вероятно: {len(report.likely)}")
    if report.unclear:
        parts.append(f"неясно: {len(report.unclear)}")
    return ", ".join(parts) if parts else "совпадений не найдено"


def top_reason(scored: ScoredFinding) -> Optional[str]:
    """Главное объяснение оценки — для компактной строки в отчёте."""
    return scored.reasons[0] if scored.reasons else None
