"""Opt-in tracker integrations.

Tracker I/O is deliberately separate from the scan client. Scan targets use
GuardedClient; tracker calls use an ordinary httpx.AsyncClient with an explicit
timeout, retry budget, and per-run API-call cap.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable

import httpx
import yaml

from .cvss import rating
from .fingerprints import result_fingerprint

SCHEMA_VERSION = "ledgerprobe-integrations/1"
_PROVIDERS = {"jira", "linear"}
_PRIORITIES = {
    "critical": "Highest", "high": "High", "medium": "Medium",
    "low": "Low", "none": "Lowest",
}
_LINEAR_PRIORITIES = {"critical": 1, "high": 2, "medium": 3, "low": 4, "none": 0}
_INLINE_SECRET = re.compile(
    r"^(?:Bearer\s+|Basic\s+|xox[baprs]-|gh[pousr]_|lin_api_|sk-|eyJ[A-Za-z0-9_-]{5,}\.)"
)
_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{1,63}\Z")
_LABEL = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
_RETAINED_EVIDENCE = {
    "confirm_runs", "overlap_count", "canary_matched", "nonexistent_skipped",
}
_HTTP_RETRY_STATUS = {429, 500, 502, 503, 504}


class TrackerError(RuntimeError):
    """A sanitized tracker failure; never contains a URL, body or credential."""


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, str) or key in result:
            raise ValueError("integration YAML mapping keys must be unique strings")
        result[key] = loader.construct_object(value_node, deep=True)
    return result


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def _keys(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError("missing or unknown integration fields")


def _text(value, name):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _url(value, name):
    _text(value, name)
    try:
        parsed = httpx.URL(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be a valid HTTPS URL") from None
    if parsed.scheme not in {"https", "http"} or not parsed.host:
        raise ValueError(f"{name} must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{name} must not contain credentials, query or fragment")
    if parsed.scheme != "https" and parsed.host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError(f"{name} requires HTTPS except loopback tests")
    return value.rstrip("/")


def _env_name(value, name):
    _text(value, name)
    if not _ENV_NAME.fullmatch(value) or _INLINE_SECRET.match(value):
        raise ValueError(f"{name} must be an environment variable name, never a credential")
    return value


def _reject_inline(value):
    if isinstance(value, str) and _INLINE_SECRET.match(value):
        raise ValueError("inline credentials are not allowed; reference an environment variable")
    if isinstance(value, dict):
        for item in value.values():
            _reject_inline(item)
    elif isinstance(value, list):
        for item in value:
            _reject_inline(item)


def _positive_int(value, name, maximum=None):
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise ValueError(f"{name} must be an integer from 1 to {maximum or 'unbounded'}")
    return value


@dataclass(frozen=True)
class TrackerConfig:
    provider: str
    target_label: str
    token_env: str
    base_url: str | None = None
    endpoint: str | None = None
    project: str | None = None
    team_id: str | None = None
    email_env: str | None = None
    issue_type: str = "Task"
    labels: tuple[str, ...] = ()
    components: tuple[str, ...] = ()
    assignee: str | None = None
    priority_map: dict[str, str] = field(default_factory=lambda: dict(_PRIORITIES))
    priority_numbers: dict[str, int] = field(default_factory=lambda: dict(_LINEAR_PRIORITIES))
    label_ids: dict[str, str] = field(default_factory=dict)
    state_open_id: str | None = None
    state_resolved_id: str | None = None
    reopen_transition: str = "Reopen"
    resolved_transition: str = "Done"
    auto_close: bool = False
    comment_cooldown_days: int = 7
    max_new_tickets_per_run: int = 20
    max_api_calls: int = 100
    timeout_seconds: float = 10.0
    retry_attempts: int = 3


@dataclass(frozen=True)
class SlackConfig:
    webhook_url_env: str | None = None


@dataclass(frozen=True)
class IntegrationsConfig:
    tracker: TrackerConfig
    slack: SlackConfig


def load_integrations(path: str | Path) -> IntegrationsConfig:
    try:
        with Path(path).open(encoding="utf-8") as stream:
            document = yaml.load(stream, Loader=_Loader)
    except (OSError, yaml.YAMLError):
        raise ValueError("integrations configuration could not be read") from None
    if not isinstance(document, dict):
        raise ValueError("integrations configuration must be a mapping")
    _keys(document, {"schema_version", "tracker", "slack"}, {"schema_version", "tracker"})
    if document["schema_version"] != SCHEMA_VERSION:
        raise ValueError("integrations configuration schema mismatch")
    _reject_inline(document)
    tracker = document["tracker"]
    if not isinstance(tracker, dict):
        raise ValueError("tracker must be a mapping")
    provider = tracker.get("provider")
    if provider not in _PROVIDERS:
        raise ValueError("tracker.provider must be jira or linear")
    common = {
        "provider", "target_label", "token_env", "email_env", "labels", "components",
        "assignee", "priority_map", "priority_numbers", "label_ids", "auto_close",
        "comment_cooldown_days", "max_new_tickets_per_run", "max_api_calls",
        "timeout_seconds", "retry_attempts",
    }
    allowed = set(common)
    if provider == "jira":
        allowed |= {"base_url", "project", "issue_type", "reopen_transition", "resolved_transition"}
        required = {"provider", "base_url", "project", "token_env", "target_label"}
    else:
        allowed |= {"endpoint", "team_id", "state_open_id", "state_resolved_id"}
        required = {"provider", "endpoint", "team_id", "token_env", "target_label"}
    _keys(tracker, allowed, required)

    target_label = tracker["target_label"]
    if not isinstance(target_label, str) or not _LABEL.fullmatch(target_label):
        raise ValueError("tracker.target_label must be a safe 1-64 character label")
    token_env = _env_name(tracker["token_env"], "tracker.token_env")
    email_env = tracker.get("email_env")
    if email_env is not None:
        _env_name(email_env, "tracker.email_env")

    labels = tracker.get("labels", [])
    components = tracker.get("components", [])
    for value, name in ((labels, "tracker.labels"), (components, "tracker.components")):
        if (not isinstance(value, list) or any(not isinstance(item, str) or not item.strip()
                                                for item in value)
                or len(set(value)) != len(value)):
            raise ValueError(f"{name} must contain unique nonempty strings")
    priority_map = tracker.get("priority_map", dict(_PRIORITIES))
    if (not isinstance(priority_map, dict) or set(priority_map) - set(_PRIORITIES)
            or any(not isinstance(value, str) or not value.strip()
                   for value in priority_map.values())):
        raise ValueError("tracker.priority_map must map CVSS ratings to nonempty strings")
    priority_numbers = tracker.get("priority_numbers", dict(_LINEAR_PRIORITIES))
    if (not isinstance(priority_numbers, dict) or set(priority_numbers) - set(_PRIORITIES)
            or any(type(value) is not int or not 0 <= value <= 4
                   for value in priority_numbers.values())):
        raise ValueError("tracker.priority_numbers must map CVSS ratings to 0..4")
    label_ids = tracker.get("label_ids", {})
    if (not isinstance(label_ids, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                               or not k or not v for k, v in label_ids.items())):
        raise ValueError("tracker.label_ids must be a string mapping")
    auto_close = tracker.get("auto_close", False)
    if type(auto_close) is not bool:
        raise ValueError("tracker.auto_close must be boolean")
    cooldown = _positive_int(tracker.get("comment_cooldown_days", 7), "tracker.comment_cooldown_days")
    maximum = _positive_int(tracker.get("max_new_tickets_per_run", 20),
                            "tracker.max_new_tickets_per_run")
    api_cap = _positive_int(tracker.get("max_api_calls", 100), "tracker.max_api_calls")
    retries = tracker.get("retry_attempts", 3)
    if type(retries) is not int or not 0 <= retries <= 5:
        raise ValueError("tracker.retry_attempts must be from 0 to 5")
    timeout = tracker.get("timeout_seconds", 10.0)
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or not 0 < timeout <= 60:
        raise ValueError("tracker.timeout_seconds must be greater than 0 and at most 60")

    values = dict(
        provider=provider, target_label=target_label, token_env=token_env,
        base_url=_url(tracker["base_url"], "tracker.base_url") if provider == "jira" else None,
        endpoint=_url(tracker["endpoint"], "tracker.endpoint") if provider == "linear" else None,
        project=tracker.get("project"), team_id=tracker.get("team_id"),
        email_env=email_env, issue_type=tracker.get("issue_type", "Task"),
        labels=tuple(labels), components=tuple(components), assignee=tracker.get("assignee"),
        priority_map=dict(priority_map), priority_numbers=dict(priority_numbers),
        label_ids=dict(label_ids), state_open_id=tracker.get("state_open_id"),
        state_resolved_id=tracker.get("state_resolved_id"),
        reopen_transition=tracker.get("reopen_transition", "Reopen"),
        resolved_transition=tracker.get("resolved_transition", "Done"),
        auto_close=auto_close, comment_cooldown_days=cooldown,
        max_new_tickets_per_run=maximum, max_api_calls=api_cap,
        timeout_seconds=float(timeout), retry_attempts=retries,
    )
    if provider == "jira":
        _text(values["project"], "tracker.project")
        _text(values["issue_type"], "tracker.issue_type")
        _text(values["reopen_transition"], "tracker.reopen_transition")
        _text(values["resolved_transition"], "tracker.resolved_transition")
    else:
        _text(values["team_id"], "tracker.team_id")
        if values["state_open_id"] is not None:
            _text(values["state_open_id"], "tracker.state_open_id")
        if values["state_resolved_id"] is not None:
            _text(values["state_resolved_id"], "tracker.state_resolved_id")

    slack = document.get("slack", {})
    if not isinstance(slack, dict):
        raise ValueError("slack must be a mapping")
    _keys(slack, {"webhook_url_env"})
    slack_env = slack.get("webhook_url_env")
    if slack_env is not None:
        _env_name(slack_env, "slack.webhook_url_env")
    return IntegrationsConfig(TrackerConfig(**values), SlackConfig(slack_env))


@dataclass
class Comment:
    body: str
    created_at: datetime
    identifier: str = ""


@dataclass
class Ticket:
    key: str
    url: str
    title: str
    description: str
    state: str
    labels: list[str]
    created_at: datetime
    comments: list[Comment] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = ""

    @property
    def open(self) -> bool:
        return self.state != "closed"


def fingerprint_label(fingerprint: str) -> str:
    return "lp-" + hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:16]


def target_slug(target: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", target.lower()).strip("-")[:40]
    return "lp-target-" + (slug or "unknown")


def label_set(fingerprint: str, target: str, configured: Iterable[str] = ()) -> list[str]:
    values = [fingerprint_label(fingerprint), target_slug(target), *configured]
    return list(dict.fromkeys(value for value in values if value))


def marker_line(fingerprint: str, target: str) -> str:
    return f"ledgerprobe-fingerprint: {fingerprint}; target: {target}"


def state_line(metadata: dict[str, Any]) -> str:
    return "ledgerprobe-state: " + json.dumps(metadata, sort_keys=True, separators=(",", ":"),
                                              ensure_ascii=True)


def parse_state(text: str | None) -> dict[str, Any]:
    if not isinstance(text, str):
        return {}
    found = {}
    for line in text.splitlines():
        if line.startswith("ledgerprobe-state: "):
            try:
                value = json.loads(line.removeprefix("ledgerprobe-state: "))
            except ValueError:
                continue
            if isinstance(value, dict):
                found = value
    return found


def _safe_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        return {}
    output = {key: evidence[key] for key in _RETAINED_EVIDENCE
              if isinstance(evidence.get(key), (int, float, bool)) and not isinstance(evidence.get(key), str)}
    hashes = evidence.get("shape_hashes")
    if isinstance(hashes, dict):
        safe_hashes = {key: value for key, value in hashes.items()
                       if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{16,64}", value)}
        if safe_hashes:
            output["shape_hashes"] = safe_hashes
    statuses = evidence.get("control_statuses")
    if isinstance(statuses, dict):
        safe_statuses = {key: value for key, value in statuses.items()
                         if isinstance(value, int) and not isinstance(value, bool)}
        if safe_statuses:
            output["control_statuses"] = safe_statuses
    return output


def finding_metadata(result: dict) -> dict[str, Any]:
    cvss = result.get("cvss") if isinstance(result.get("cvss"), dict) else {}
    return {
        "confidence": result.get("confidence"),
        "cvss_score": cvss.get("score", result.get("cvss_score")),
        "cvss_rating": cvss.get("rating"),
        "reason": _safe_text(result.get("reason")),
        "evidence": _safe_evidence(result.get("evidence")),
    }


def ticket_title(result: dict) -> str:
    return _safe_text(
        f"[LedgerProbe] {result.get('name', result.get('rule_id', 'finding'))} - "
        f"{result.get('method', 'GET')} {result.get('path_template', result.get('path', ''))}")


def _safe_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+", "[redacted]", text)
    text = re.sub(r"(?i)\bSECRET[-_A-Za-z0-9]*", "[redacted]", text)
    return text


def _safe_ci_url(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = httpx.URL(value)
    except (TypeError, ValueError):
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.host:
        return None
    safe = f"{parsed.scheme}://{parsed.host}"
    if parsed.port:
        safe += f":{parsed.port}"
    safe += parsed.path
    return _safe_text(safe)


def ticket_body(result: dict, *, target: str, fingerprint: str, ci_url: str | None,
                metadata: dict[str, Any] | None = None) -> str:
    cvss = result.get("cvss") if isinstance(result.get("cvss"), dict) else {}
    evidence = _safe_evidence(result.get("evidence"))
    lines = [
        marker_line(fingerprint, target),
        state_line(metadata or finding_metadata(result)),
        f"verdict: {result.get('verdict', 'FAIL')}",
        f"reason: {_safe_text(result.get('reason')) or 'not recorded'}",
        f"confidence: {result.get('confidence') or 'not recorded'}",
        f"cvss_vector: {cvss.get('vector', result.get('cvss_score', 'not recorded'))}",
        f"cvss_score: {cvss.get('score', result.get('cvss_score', 'not recorded'))}",
        f"cvss_rating: {cvss.get('rating') or rating(float(cvss.get('score', result.get('cvss_score', 0) or 0)))}",
        f"path_template: {_safe_text(result.get('path_template', result.get('path', 'not recorded')))}",
        f"roles: {_safe_text(', '.join(result.get('identity_roles') or [])) or 'not recorded'}",
        f"evidence: {json.dumps(evidence, sort_keys=True, separators=(',', ':')) if evidence else 'none'}",
        f"fingerprint: {fingerprint}",
        f"target: {target}",
    ]
    safe_ci = _safe_ci_url(ci_url)
    if safe_ci:
        lines.append(f"ci_run: {safe_ci}")
    remediation = result.get("remediation")
    if isinstance(remediation, str) and remediation.strip():
        lines.append(f"remediation: {_safe_text(remediation.strip())}")
    return "\n".join(lines)


def ticket_draft(result: dict, *, target: str, fingerprint: str, ci_url: str | None,
                 config: TrackerConfig) -> dict[str, Any]:
    metadata = finding_metadata(result)
    cvss = result.get("cvss") if isinstance(result.get("cvss"), dict) else {}
    rating_name = (cvss.get("rating") or result.get("severity") or "none").lower()
    return {
        **result,
        "ticket_title": ticket_title(result),
        "ticket_body": ticket_body(result, target=target, fingerprint=fingerprint,
                                   ci_url=ci_url, metadata=metadata),
        "ticket_labels": label_set(fingerprint, target, config.labels),
        "ticket_metadata": metadata,
        "ticket_priority": config.priority_map.get(rating_name, config.priority_map.get("none", "")),
        "ticket_priority_number": config.priority_numbers.get(rating_name, 0),
        "ticket_components": list(config.components),
        "ticket_assignee": config.assignee,
    }


class Tracker:
    async def find(self, fingerprint: str, target: str) -> Ticket | None:
        tickets = await self.find_all(fingerprint, target)
        return min(tickets, key=lambda item: item.created_at) if tickets else None

    async def find_all(self, fingerprint: str, target: str) -> list[Ticket]:
        raise NotImplementedError

    async def create(self, finding: dict) -> Ticket:
        raise NotImplementedError

    async def comment(self, ticket: Ticket, text: str) -> Comment:
        raise NotImplementedError

    async def reopen(self, ticket: Ticket) -> None:
        raise NotImplementedError

    async def transition_resolved(self, ticket: Ticket) -> None:
        raise NotImplementedError

    async def list_open_for_target(self, target: str) -> list[Ticket]:
        raise NotImplementedError

    async def add_label(self, ticket: Ticket, label: str) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class FakeTracker(Tracker):
    """In-memory tracker used by tests and dry-run planning."""

    def __init__(self, *, now: datetime | None = None, start: int = 0):
        self.now = now or datetime.now(timezone.utc)
        self._next = start
        self.tickets: dict[str, Ticket] = {}
        self.calls: list[str] = []

    def _clock(self) -> datetime:
        return self.now

    async def find_all(self, fingerprint: str, target: str) -> list[Ticket]:
        fp_label, target_label = fingerprint_label(fingerprint), target_slug(target)
        found = [ticket for ticket in self.tickets.values()
                 if fp_label in ticket.labels and target_label in ticket.labels]
        if not found:
            marker = marker_line(fingerprint, target)
            found = [ticket for ticket in self.tickets.values() if marker in ticket.description]
        return sorted(found, key=lambda item: item.created_at)

    async def create(self, finding: dict) -> Ticket:
        self._next += 1
        key = f"FAKE-{self._next}"
        ticket = Ticket(
            key=key, url=f"https://fake.test/{key}",
            title=finding["ticket_title"], description=finding["ticket_body"],
            state="open", labels=list(dict.fromkeys(finding.get("ticket_labels", []))),
            created_at=self._clock(), metadata=dict(finding.get("ticket_metadata", {})),
            id=key,
        )
        self.tickets[key] = ticket
        self.calls.append(f"create:{key}")
        return ticket

    async def comment(self, ticket: Ticket, text: str) -> Comment:
        comment = Comment(body=text, created_at=self._clock(), identifier=f"C{len(ticket.comments) + 1}")
        ticket.comments.append(comment)
        self.calls.append(f"comment:{ticket.key}")
        return comment

    async def reopen(self, ticket: Ticket) -> None:
        ticket.state = "open"
        if "lp-regression" not in ticket.labels:
            ticket.labels.append("lp-regression")
        self.calls.append(f"reopen:{ticket.key}")

    async def transition_resolved(self, ticket: Ticket) -> None:
        ticket.state = "closed"
        self.calls.append(f"resolve:{ticket.key}")

    async def list_open_for_target(self, target: str) -> list[Ticket]:
        label = target_slug(target)
        return [ticket for ticket in self.tickets.values() if ticket.open and label in ticket.labels]

    async def add_label(self, ticket: Ticket, label: str) -> None:
        if label not in ticket.labels:
            ticket.labels.append(label)
        self.calls.append(f"label:{ticket.key}:{label}")

    def seed(self, finding: dict, *, state: str = "open", created_at: datetime | None = None,
             comments: Iterable[tuple[str, datetime]] = ()) -> Ticket:
        self._next += 1
        key = f"FAKE-{self._next}"
        ticket = Ticket(
            key=key, url=f"https://fake.test/{key}", title=finding["ticket_title"],
            description=finding["ticket_body"], state=state, labels=list(finding["ticket_labels"]),
            created_at=created_at or self._clock(), metadata=dict(finding["ticket_metadata"]),
        )
        ticket.comments = [Comment(body=text, created_at=when, identifier=f"C{i + 1}")
                           for i, (text, when) in enumerate(comments)]
        self.tickets[key] = ticket
        return ticket


def _retry_after(response: httpx.Response, attempt: int) -> float:
    value = response.headers.get("retry-after")
    if value:
        try:
            seconds = float(value)
            if seconds >= 0:
                return min(seconds, 60.0)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                return max(0.0, min((when - datetime.now(timezone.utc)).total_seconds(), 60.0))
            except (TypeError, ValueError, OverflowError):
                pass
    return min(0.25 * (2 ** attempt), 5.0)


class HttpTracker(Tracker):
    def __init__(self, config: TrackerConfig, token: str, *, transport=None,
                 sleep=None, now: datetime | None = None):
        self.config = config
        self.token = token
        self.calls = 0
        self.sleep = sleep or asyncio.sleep
        self.now = now or datetime.now(timezone.utc)
        headers = {"Accept": "application/json", "User-Agent": "LedgerProbe/1.0"}
        if config.provider == "jira":
            email = os.environ.get(config.email_env) if config.email_env else None
            if email:
                headers["Authorization"] = "Basic " + base64.b64encode(
                    f"{email}:{token}".encode("utf-8")).decode("ascii")
            else:
                headers["Authorization"] = "Bearer " + token
        else:
            headers["Authorization"] = token
        self.client = httpx.AsyncClient(timeout=config.timeout_seconds, transport=transport,
                                        headers=headers)
        self._linear_labels: dict[str, str] = dict(config.label_ids)

    async def close(self) -> None:
        await self.client.aclose()

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        attempts = self.config.retry_attempts + 1
        for attempt in range(attempts):
            if self.calls >= self.config.max_api_calls:
                raise TrackerError("tracker API call cap reached")
            self.calls += 1
            try:
                response = await self.client.request(method, url, **kwargs)
            except httpx.HTTPError:
                if attempt + 1 >= attempts:
                    raise TrackerError("tracker request failed") from None
                await self.sleep(min(0.25 * (2 ** attempt), 5.0))
                continue
            if response.status_code == 429 or 500 <= response.status_code < 600:
                if attempt + 1 >= attempts:
                    raise TrackerError(f"tracker request failed (HTTP {response.status_code})")
                await self.sleep(_retry_after(response, attempt))
                continue
            if not 200 <= response.status_code < 300:
                raise TrackerError(f"tracker request failed (HTTP {response.status_code})")
            return response
        raise TrackerError("tracker request failed")

    async def _json(self, method: str, url: str, **kwargs) -> dict:
        response = await self._request(method, url, **kwargs)
        try:
            value = response.json()
        except ValueError:
            raise TrackerError("tracker returned invalid JSON") from None
        if not isinstance(value, dict):
            raise TrackerError("tracker returned an unexpected response")
        return value

    def _url(self, path: str) -> str:
        base = self.config.base_url if self.config.provider == "jira" else self.config.endpoint
        if not base:
            raise TrackerError("tracker endpoint is not configured")
        return base.rstrip("/") + path


def _adf(text: str) -> dict:
    return {"type": "doc", "version": 1, "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": line}]}
        for line in text.splitlines() or [""]
    ]}


def _adf_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return ""
    chunks = []
    if isinstance(value.get("text"), str):
        chunks.append(value["text"])
    for item in value.get("content", []) or []:
        text = _adf_text(item)
        if text:
            chunks.append(text)
    return "\n".join(chunks)


def _parse_time(value: Any, fallback: datetime) -> datetime:
    if not isinstance(value, str):
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return fallback


class JiraTracker(HttpTracker):
    _FIELDS = "key,summary,status,labels,description,created,comment,priority,components,assignee"

    async def _search(self, jql: str) -> list[dict]:
        data = await self._json(
            "GET", self._url("/rest/api/3/search"),
            params={"jql": jql, "fields": self._FIELDS, "maxResults": 50},
        )
        issues = data.get("issues", [])
        return issues if isinstance(issues, list) else []

    def _ticket(self, issue: dict) -> Ticket:
        fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
        comments = []
        raw_comments = fields.get("comment", {}).get("comments", []) if isinstance(fields.get("comment"), dict) else []
        for item in raw_comments:
            if isinstance(item, dict):
                comments.append(Comment(
                    body=_adf_text(item.get("body")),
                    created_at=_parse_time(item.get("created"), self.now),
                    identifier=str(item.get("id", "")),
                ))
        description = _adf_text(fields.get("description"))
        state_name = str((fields.get("status") or {}).get("name", "open")).lower()
        closed = state_name in {"done", "closed", "resolved", "cancelled", "canceled"}
        labels = [str(item) for item in fields.get("labels", []) if isinstance(item, str)]
        key = str(issue.get("key", "unknown"))
        url = str(issue.get("self") or self._url(f"/browse/{key}"))
        metadata = parse_state(description)
        for comment in comments:
            metadata = parse_state(comment.body) or metadata
        return Ticket(key=key, url=url, title=str(fields.get("summary", "")),
                      description=description, state="closed" if closed else "open",
                      labels=labels, created_at=_parse_time(fields.get("created"), self.now),
                      comments=comments, metadata=metadata, id=key)

    async def find_all(self, fingerprint: str, target: str) -> list[Ticket]:
        fp_label, target_label = fingerprint_label(fingerprint), target_slug(target)
        jql = (f'project = "{self.config.project}" AND labels = "{fp_label}" '
               f'AND labels = "{target_label}"')
        issues = await self._search(jql)
        if not issues:
            marker = marker_line(fingerprint, target)
            issues = await self._search(
                f'project = "{self.config.project}" AND text ~ "{marker}"')
        return [self._ticket(issue) for issue in issues if isinstance(issue, dict)]

    async def create(self, finding: dict) -> Ticket:
        fields = {
            "project": {"key": self.config.project},
            "issuetype": {"name": self.config.issue_type},
            "summary": finding["ticket_title"],
            "description": _adf(finding["ticket_body"]),
            "labels": list(dict.fromkeys(finding.get("ticket_labels", []))),
        }
        if finding.get("ticket_priority"):
            fields["priority"] = {"name": finding["ticket_priority"]}
        if finding.get("ticket_components"):
            fields["components"] = [{"name": item} for item in finding["ticket_components"]]
        if finding.get("ticket_assignee"):
            fields["assignee"] = {"name": finding["ticket_assignee"]}
        data = await self._json("POST", self._url("/rest/api/3/issue"),
                                json={"fields": fields})
        key = str(data.get("key", "unknown"))
        url = str(data.get("self") or self._url(f"/browse/{key}"))
        return Ticket(key=key, url=url, title=finding["ticket_title"],
                      description=finding["ticket_body"], state="open",
                      labels=list(fields["labels"]), created_at=self.now,
                      metadata=dict(finding.get("ticket_metadata", {})), id=key)

    async def comment(self, ticket: Ticket, text: str) -> Comment:
        data = await self._json(
            "POST", self._url(f"/rest/api/3/issue/{ticket.key}/comment"),
            json={"body": _adf(text)},
        )
        return Comment(body=text, created_at=_parse_time(data.get("created"), self.now),
                       identifier=str(data.get("id", "")))

    async def _transition(self, ticket: Ticket, name: str) -> None:
        data = await self._json("GET", self._url(f"/rest/api/3/issue/{ticket.key}/transitions"))
        transitions = data.get("transitions", [])
        selected = next((item for item in transitions
                         if isinstance(item, dict) and str(item.get("name", "")).lower() == name.lower()),
                        None)
        if selected is None:
            raise TrackerError("tracker transition is unavailable")
        await self._request("POST", self._url(f"/rest/api/3/issue/{ticket.key}/transitions"),
                            json={"transition": {"id": selected.get("id")}})

    async def reopen(self, ticket: Ticket) -> None:
        await self._transition(ticket, self.config.reopen_transition)
        ticket.state = "open"
        await self.add_label(ticket, "lp-regression")

    async def transition_resolved(self, ticket: Ticket) -> None:
        await self._transition(ticket, self.config.resolved_transition)
        ticket.state = "closed"

    async def add_label(self, ticket: Ticket, label: str) -> None:
        labels = list(dict.fromkeys([*ticket.labels, label]))
        await self._request("PUT", self._url(f"/rest/api/3/issue/{ticket.key}"),
                            json={"fields": {"labels": labels}})
        ticket.labels = labels

    async def list_open_for_target(self, target: str) -> list[Ticket]:
        jql = (f'project = "{self.config.project}" AND labels = "{target_slug(target)}" '
               'AND statusCategory != Done')
        return [self._ticket(issue) for issue in await self._search(jql)
                if isinstance(issue, dict)]


class LinearTracker(HttpTracker):
    _FIND = (
        "query LedgerProbeFind($filter: IssueFilter!) { issues(filter: $filter, first: 50) { "
        "nodes { id identifier title description url createdAt state { name type } "
        "labels { nodes { id name } } comments { nodes { id body createdAt } } } } }"
    )
    _CREATE = (
        "mutation LedgerProbeCreate($input: IssueCreateInput!) { issueCreate(input: $input) { "
        "success issue { id identifier title url } } }"
    )
    _COMMENT = (
        "mutation LedgerProbeComment($input: CommentCreateInput!) { commentCreate(input: $input) { "
        "success comment { id body createdAt } } }"
    )
    _UPDATE = (
        "mutation LedgerProbeUpdate($id: String!, $input: IssueUpdateInput!) { "
        "issueUpdate(id: $id, input: $input) { success issue { id identifier url state { name type } } } }"
    )
    _LABEL_FIND = (
        "query LedgerProbeLabel($teamId: ID!, $name: String!) { issueLabels("
        "filter: {team: {id: {eq: $teamId}}, name: {eq: $name}}, first: 1) { "
        "nodes { id name } } }"
    )
    _LABEL_CREATE = (
        "mutation LedgerProbeLabelCreate($input: IssueLabelCreateInput!) { "
        "issueLabelCreate(input: $input) { success issueLabel { id name } } }"
    )

    async def _graphql(self, query: str, variables: dict) -> dict:
        data = await self._json("POST", self._url(""),
                                json={"query": query, "variables": variables})
        if data.get("errors"):
            raise TrackerError("tracker GraphQL request failed")
        payload = data.get("data")
        if not isinstance(payload, dict):
            raise TrackerError("tracker returned an unexpected response")
        return payload

    def _ticket(self, node: dict) -> Ticket:
        state = node.get("state") if isinstance(node.get("state"), dict) else {}
        closed = str(state.get("type", "")).lower() in {"completed", "canceled", "cancelled"}
        labels = [str(item.get("name")) for item in (node.get("labels") or {}).get("nodes", [])
                  if isinstance(item, dict) and item.get("name")]
        comments = []
        for item in (node.get("comments") or {}).get("nodes", []):
            if isinstance(item, dict):
                comments.append(Comment(body=str(item.get("body", "")),
                                        created_at=_parse_time(item.get("createdAt"), self.now),
                                        identifier=str(item.get("id", ""))))
        description = str(node.get("description", ""))
        metadata = parse_state(description)
        for comment in comments:
            metadata = parse_state(comment.body) or metadata
        return Ticket(key=str(node.get("identifier") or node.get("id") or "unknown"),
                      url=str(node.get("url", "")), title=str(node.get("title", "")),
                      description=description, state="closed" if closed else "open",
                      labels=labels, created_at=_parse_time(node.get("createdAt"), self.now),
                      comments=comments, metadata=metadata, id=str(node.get("id") or ""))

    async def find_all(self, fingerprint: str, target: str) -> list[Ticket]:
        fp_label, target_label = fingerprint_label(fingerprint), target_slug(target)
        payload = await self._graphql(self._FIND, {"filter": {
            "labels": {"some": {"name": {"in": [fp_label, target_label]}}},
        }})
        nodes = (payload.get("issues") or {}).get("nodes", [])
        found = [self._ticket(node) for node in nodes
                 if isinstance(node, dict) and fp_label in self._labels(node)
                 and target_label in self._labels(node)]
        if not found:
            marker = marker_line(fingerprint, target)
            payload = await self._graphql(self._FIND, {"filter": {
                "description": {"contains": marker},
            }})
            nodes = (payload.get("issues") or {}).get("nodes", [])
            found = [self._ticket(node) for node in nodes if isinstance(node, dict)]
        return found

    @staticmethod
    def _labels(node: dict) -> list[str]:
        return [str(item.get("name")) for item in (node.get("labels") or {}).get("nodes", [])
                if isinstance(item, dict) and item.get("name")]

    async def _ensure_label(self, name: str) -> str:
        if name in self._linear_labels:
            return self._linear_labels[name]
        payload = await self._graphql(self._LABEL_FIND,
                                      {"teamId": self.config.team_id, "name": name})
        nodes = (payload.get("issueLabels") or {}).get("nodes", [])
        if nodes and isinstance(nodes[0], dict) and nodes[0].get("id"):
            self._linear_labels[name] = str(nodes[0]["id"])
            return self._linear_labels[name]
        payload = await self._graphql(self._LABEL_CREATE, {"input": {
            "teamId": self.config.team_id, "name": name,
        }})
        label = (payload.get("issueLabelCreate") or {}).get("issueLabel") or {}
        if not label.get("id"):
            raise TrackerError("tracker label creation failed")
        self._linear_labels[name] = str(label["id"])
        return self._linear_labels[name]

    async def _label_ids(self, labels: Iterable[str]) -> list[str]:
        values = [await self._ensure_label(label) for label in labels]
        return list(dict.fromkeys(values))

    async def create(self, finding: dict) -> Ticket:
        labels = list(dict.fromkeys(finding.get("ticket_labels", [])))
        payload = await self._graphql(self._CREATE, {"input": {
            "teamId": self.config.team_id,
            "title": finding["ticket_title"],
            "description": finding["ticket_body"],
            "priority": finding.get("ticket_priority_number", 0),
            "labelIds": await self._label_ids(labels),
            **({"assigneeId": finding["ticket_assignee"]} if finding.get("ticket_assignee") else {}),
        }})
        issue = (payload.get("issueCreate") or {}).get("issue") or {}
        if not issue.get("id"):
            raise TrackerError("tracker issue creation failed")
        return Ticket(key=str(issue.get("identifier") or issue["id"]), url=str(issue.get("url", "")),
                      title=finding["ticket_title"], description=finding["ticket_body"],
                      state="open", labels=labels, created_at=self.now,
                      metadata=dict(finding.get("ticket_metadata", {})), id=str(issue["id"]))

    async def comment(self, ticket: Ticket, text: str) -> Comment:
        payload = await self._graphql(self._COMMENT, {"input": {
            "issueId": ticket.id or ticket.key, "body": text,
        }})
        comment = (payload.get("commentCreate") or {}).get("comment") or {}
        if not comment.get("id"):
            raise TrackerError("tracker comment creation failed")
        return Comment(body=text, created_at=_parse_time(comment.get("createdAt"), self.now),
                       identifier=str(comment["id"]))

    async def _update(self, ticket: Ticket, values: dict) -> None:
        payload = await self._graphql(self._UPDATE, {"id": ticket.id or ticket.key, "input": values})
        if not (payload.get("issueUpdate") or {}).get("success"):
            raise TrackerError("tracker issue update failed")

    async def reopen(self, ticket: Ticket) -> None:
        if not self.config.state_open_id:
            raise TrackerError("tracker open state is not configured")
        await self._update(ticket, {"stateId": self.config.state_open_id})
        ticket.state = "open"
        await self.add_label(ticket, "lp-regression")

    async def transition_resolved(self, ticket: Ticket) -> None:
        if not self.config.state_resolved_id:
            raise TrackerError("tracker resolved state is not configured")
        await self._update(ticket, {"stateId": self.config.state_resolved_id})
        ticket.state = "closed"

    async def add_label(self, ticket: Ticket, label: str) -> None:
        labels = list(dict.fromkeys([*ticket.labels, label]))
        await self._update(ticket, {"labelIds": await self._label_ids(labels)})
        ticket.labels = labels

    async def list_open_for_target(self, target: str) -> list[Ticket]:
        payload = await self._graphql(self._FIND, {"filter": {
            "labels": {"some": {"name": {"in": [target_slug(target)]}}},
        }})
        nodes = (payload.get("issues") or {}).get("nodes", [])
        return [self._ticket(node) for node in nodes
                if isinstance(node, dict) and target_slug(target) in self._labels(node)]


def build_tracker(config: IntegrationsConfig, *, transport=None, sleep=None,
                  now: datetime | None = None) -> Tracker:
    token = os.environ.get(config.tracker.token_env)
    if not token:
        raise TrackerError("tracker token environment variable is not set")
    if config.tracker.provider == "jira":
        return JiraTracker(config.tracker, token, transport=transport, sleep=sleep, now=now)
    return LinearTracker(config.tracker, token, transport=transport, sleep=sleep, now=now)


def _open_ticket(tickets: list[Ticket]) -> Ticket | None:
    return min((ticket for ticket in tickets if ticket.open),
               key=lambda item: item.created_at, default=None)


def _latest_comment(ticket: Ticket) -> datetime | None:
    return max((comment.created_at for comment in ticket.comments), default=None)


def _material_change(ticket: Ticket, result: dict) -> str | None:
    current = finding_metadata(result)
    previous = ticket.metadata if isinstance(ticket.metadata, dict) else {}
    differences = []
    for label, key in (("confidence", "confidence"), ("cvss", "cvss_score"),
                       ("reason", "reason"), ("evidence", "evidence")):
        if previous.get(key) != current.get(key):
            differences.append(f"{label}: {previous.get(key, 'unknown')} -> {current.get(key, 'unknown')}")
    return "; ".join(differences) or None


def _comment_recent(ticket: Ticket, now: datetime, days: int) -> bool:
    latest = _latest_comment(ticket)
    return latest is not None and now - latest < timedelta(days=days)


def _retest_runs(ticket: Ticket) -> set[str]:
    found = set()
    for comment in ticket.comments:
        for line in comment.body.splitlines():
            if line.startswith("ledgerprobe-retest-passed: run "):
                found.add(line.removeprefix("ledgerprobe-retest-passed: run "))
    return found


def _suppressed_comment(ticket: Ticket, expires: str) -> bool:
    needle = f"ledgerprobe-suppressed: until {expires}"
    return any(needle in comment.body for comment in ticket.comments)


@dataclass
class TicketRun:
    counts: dict[str, int] = field(default_factory=lambda: {
        "new": 0, "regressed": 0, "resolved": 0, "suppressed": 0,
        "inconclusive": 0, "errors": 0,
    })
    actions: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tickets: list[Ticket] = field(default_factory=list)
    slack_text: str | None = None


def _ci_url() -> str | None:
    direct = os.environ.get("CI_RUN_URL")
    if direct:
        return direct
    server = os.environ.get("GITHUB_SERVER_URL")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repository and run_id:
        return f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}"
    return None


def _digest_text(run: TicketRun, ci_url: str | None) -> str:
    counts = run.counts
    lines = [
        "LedgerProbe ticket digest: "
        f"new={counts['new']} regressed={counts['regressed']} "
        f"resolved={counts['resolved']} suppressed={counts['suppressed']} "
        f"inconclusive={counts['inconclusive']} errors={counts['errors']}",
    ]
    if ci_url:
        lines.append(f"CI run: {ci_url}")
    links = [ticket for ticket in run.tickets if ticket.url][:10]
    if links:
        lines.append("Tickets:")
        lines.extend(f"- {ticket.key}: {ticket.url}" for ticket in links)
    return "\n".join(lines)


async def _deduplicate(tracker: Tracker, tickets: list[Ticket], run: TicketRun,
                       *, write: bool = True) -> Ticket | None:
    if not tickets:
        return None
    ordered = sorted(tickets, key=lambda item: item.created_at)
    oldest = ordered[0]
    for newer in ordered[1:]:
        try:
            if write:
                await tracker.comment(newer, f"Duplicate of {oldest.key}: {oldest.url}")
                await tracker.add_label(newer, "lp-duplicate")
            run.warnings.append(f"duplicate_ticket:{newer.key}")
        except TrackerError as exc:
            run.errors.append(str(exc))
    return oldest


async def _slack_send(config: IntegrationsConfig, text: str, *, transport=None,
                      now: datetime | None = None) -> None:
    if not config.slack.webhook_url_env:
        return
    url = os.environ.get(config.slack.webhook_url_env)
    if not url:
        raise TrackerError("Slack webhook environment variable is not set")
    async with httpx.AsyncClient(timeout=10.0, transport=transport) as client:
        try:
            response = await client.post(url, json={"text": text})
        except httpx.HTTPError:
            raise TrackerError("Slack delivery failed") from None
    if not 200 <= response.status_code < 300:
        raise TrackerError(f"Slack delivery failed (HTTP {response.status_code})")


async def process_tickets(results: list[dict], *, config: IntegrationsConfig, target: str,
                          mode: str = "dry-run", tracker: Tracker | None = None,
                          transport=None, sleep=None, now: datetime | None = None,
                          ci_url: str | None = None, slack_transport=None, emit=None) -> TicketRun:
    """Plan and optionally execute lifecycle actions; never part of scan verdicts."""
    if mode not in {"dry-run", "plan", "apply"}:
        raise ValueError("ticket mode must be dry-run, plan or apply")
    emit = emit or print
    now = now or datetime.now(timezone.utc)
    run = TicketRun()
    owns_tracker = tracker is None and mode in {"plan", "apply"}
    if tracker is None:
        tracker = FakeTracker(now=now) if mode == "dry-run" else build_tracker(
            config, transport=transport, sleep=sleep, now=now)
    target_label = config.tracker.target_label
    ci_url = ci_url if ci_url is not None else _ci_url()
    try:
        by_fingerprint: dict[str, dict] = {}
        for result in results:
            fp = result_fingerprint(result)
            by_fingerprint.setdefault(fp, result)
        existing: dict[str, Ticket] = {}
        lookup_failed: set[str] = set()
        for fp, result in by_fingerprint.items():
            try:
                tickets = await tracker.find_all(fp, target_label)
                ticket = await _deduplicate(tracker, tickets, run, write=mode == "apply")
            except TrackerError as exc:
                run.errors.append(str(exc))
                lookup_failed.add(fp)
                continue
            if ticket:
                existing[fp] = ticket

        create_drafts = []
        for fp, result in by_fingerprint.items():
            if fp in lookup_failed:
                continue
            status = result.get("status")
            if status == "suppressed":
                run.counts["suppressed"] += 1
                ticket = existing.get(fp)
                expires = (result.get("suppression") or {}).get("expires", "unknown")
                if ticket and ticket.open and not _suppressed_comment(ticket, expires):
                    text = f"ledgerprobe-suppressed: until {expires}"
                    await _execute_comment(tracker, ticket, text, mode, run, result, fp, target_label, emit=emit)
                continue
            if status == "failed" and result.get("verdict") == "FAIL":
                ticket = existing.get(fp)
                if ticket is None:
                    create_drafts.append(ticket_draft(
                        result, target=target_label, fingerprint=fp, ci_url=ci_url, config=config.tracker))
                    continue
                if not ticket.open:
                    try:
                        await _execute_reopen(tracker, ticket, mode, run, result, fp, target_label)
                    except TrackerError as exc:
                        run.errors.append(str(exc))
                        continue
                    text = f"ledgerprobe-regression: finding failed again\n{state_line(finding_metadata(result))}"
                    await _execute_comment(tracker, ticket, text, mode, run, result, fp, target_label, emit=emit)
                    run.counts["regressed"] += 1
                    continue
                change = _material_change(ticket, result)
                if change and not _comment_recent(ticket, now, config.tracker.comment_cooldown_days):
                    text = f"ledgerprobe-material-change: {change}\n{state_line(finding_metadata(result))}"
                    await _execute_comment(tracker, ticket, text, mode, run, result, fp, target_label, emit=emit)
                else:
                    run.actions.append({"kind": "noop", "fingerprint": fp,
                                        "rule_id": result.get("rule_id"), "ticket": ticket.key})
                continue
            if status == "passed":
                ticket = existing.get(fp)
                if ticket and ticket.open and result.get("verdict") == "PASS":
                    marker = f"ledgerprobe-retest-passed: run {now.isoformat()}"
                    await _execute_comment(tracker, ticket, marker, mode, run, result, fp,
                                           target_label, dedupe_marker=True, emit=emit)
                    try:
                        if mode == "apply":
                            await tracker.add_label(ticket, "lp-retest-passed")
                    except TrackerError as exc:
                        run.errors.append(str(exc))
                    if config.tracker.auto_close and len(_retest_runs(ticket) | {now.isoformat()}) >= 2:
                        try:
                            if mode == "apply":
                                await tracker.transition_resolved(ticket)
                            run.actions.append({"kind": "resolve", "fingerprint": fp,
                                                "rule_id": result.get("rule_id"), "ticket": ticket.key,
                                                "url": ticket.url})
                            run.counts["resolved"] += 1
                        except TrackerError as exc:
                            run.errors.append(str(exc))
                continue
            if status in {"inconclusive", "skipped"}:
                run.counts["inconclusive"] += 1
            elif status == "error":
                run.counts["errors"] += 1

        maximum = config.tracker.max_new_tickets_per_run
        selected = create_drafts[:maximum]
        overflow = create_drafts[maximum:]
        for draft in selected:
            try:
                if mode == "apply":
                    ticket = await tracker.create(draft)
                    # Re-query after create: a concurrent run may have created the
                    # same key. Keep the oldest and mark any newer ticket duplicate.
                    try:
                        siblings = await tracker.find_all(draft["fingerprint"], target_label)
                        kept = await _deduplicate(tracker, siblings, run, write=mode == "apply")
                        if kept is not None:
                            ticket = kept
                    except TrackerError as exc:
                        run.errors.append(str(exc))
                    run.tickets.append(ticket)
                else:
                    ticket = None
                run.actions.append({"kind": "create", "fingerprint": draft["fingerprint"],
                                    "rule_id": draft.get("rule_id"),
                                    "ticket": ticket.key if ticket else "planned",
                                    "url": ticket.url if ticket else ""})
                run.counts["new"] += 1
            except TrackerError as exc:
                run.errors.append(str(exc))
        if overflow:
            rule_ids = sorted({str(item.get("rule_id")) for item in overflow})
            summary = {
                "ticket_title": "[LedgerProbe] New-ticket flood summary",
                "ticket_body": "\n".join([
                    f"ledgerprobe-fingerprint: flood-summary:{now.isoformat()}; target: {target_label}",
                    "summary: new-ticket cap reached",
                    f"suppressed_count: {len(overflow)}",
                    f"rule_ids: {', '.join(rule_ids)}",
                ]),
                "ticket_labels": ["lp-flood-summary", target_slug(target_label), *config.tracker.labels],
                "ticket_metadata": {"kind": "flood_summary", "rule_ids": rule_ids},
                "fingerprint": "",
                "rule_id": "flood-summary",
            }
            try:
                if mode == "apply":
                    ticket = await tracker.create(summary)
                    run.tickets.append(ticket)
                else:
                    ticket = None
                run.actions.append({"kind": "summary", "fingerprint": "",
                                    "rule_id": "flood-summary",
                                    "ticket": ticket.key if ticket else "planned",
                                    "url": ticket.url if ticket else ""})
                run.counts["new"] += 1
                run.warnings.append(f"new_ticket_cap:{len(overflow)}")
            except TrackerError as exc:
                run.errors.append(str(exc))
        for action in run.actions:
            if action["kind"] == "create":
                emit(f"[tickets] create {action['fingerprint']} {action.get('rule_id')}")
            elif action["kind"] == "summary":
                emit("[tickets] create-summary rule=flood-summary")
            elif action["kind"] == "comment":
                emit(f"[tickets] comment {action['fingerprint']} {action.get('rule_id')} ticket={action['ticket']}")
            elif action["kind"] == "reopen":
                emit(f"[tickets] reopen {action['fingerprint']} {action.get('rule_id')} ticket={action['ticket']}")
            elif action["kind"] == "resolve":
                emit(f"[tickets] resolve {action['fingerprint']} {action.get('rule_id')} ticket={action['ticket']}")
            elif action["kind"] == "noop":
                emit(f"[tickets] noop {action['fingerprint']} {action.get('rule_id')} ticket={action['ticket']}")
        run.slack_text = _digest_text(run, ci_url)
        if mode == "apply":
            try:
                await _slack_send(config, run.slack_text, transport=slack_transport, now=now)
            except TrackerError as exc:
                run.errors.append(str(exc))
        elif config.slack.webhook_url_env:
            emit("[tickets] dry-run slack digest planned (network disabled)")
        return run
    finally:
        if owns_tracker and tracker is not None:
            await tracker.close()


async def _execute_comment(tracker: Tracker, ticket: Ticket, text: str, mode: str, run: TicketRun,
                           result: dict, fingerprint: str, target: str,
                           dedupe_marker: bool = False, emit=None) -> None:
    emit = emit or print
    if dedupe_marker and any(text in comment.body for comment in ticket.comments):
        return
    try:
        if mode == "apply":
            old = ticket.metadata
            await tracker.comment(ticket, text)
            state = parse_state(text)
            if state:
                ticket.metadata = state
        elif mode == "plan":
            emit("[tickets] plan mode: read-only tracker lookups; no writes")
        else:
            ticket.metadata = old
        run.actions.append({"kind": "comment", "fingerprint": fingerprint,
                            "rule_id": result.get("rule_id"), "ticket": ticket.key,
                            "url": ticket.url})
    except TrackerError as exc:
        run.errors.append(str(exc))


async def _execute_reopen(tracker: Tracker, ticket: Ticket, mode: str, run: TicketRun,
                          result: dict, fingerprint: str, target: str) -> None:
    if mode == "apply":
        await tracker.reopen(ticket)
    run.actions.append({"kind": "reopen", "fingerprint": fingerprint,
                        "rule_id": result.get("rule_id"), "ticket": ticket.key,
                        "url": ticket.url})
