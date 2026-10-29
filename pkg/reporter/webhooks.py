"""Explicit, single-attempt notifications through a caller-owned HTTP client.

Use a separate GuardedClient that permits POSTs; scan read-only policy is not
changed here. HTTPS is required except HTTP localhost/loopback for tests/dev.
Only allowlisted metadata leaves the process: messages, assertions, auth context,
response bodies, and endpoint query/fragment values are deliberately excluded.
"""

import ipaddress
from urllib.parse import urlsplit


_KINDS = {"slack", "teams", "jira", "linear", "generic"}
_FIELDS = ("rule_id", "name", "severity", "owasp_category", "cvss_score", "path", "method", "status")
_LINEAR_MUTATION = (
    "mutation LedgerProbeIssue($input: IssueCreateInput!) { "
    "issueCreate(input: $input) { success } }"
)


def _validate(webhook):
    if not isinstance(webhook, dict):
        raise ValueError("Webhook configuration must be a dictionary")
    kind = webhook.get("kind")
    if not isinstance(kind, str) or kind not in _KINDS:
        raise ValueError("Unsupported webhook kind")
    url = webhook.get("url")
    if not isinstance(url, str) or not url or any(c.isspace() or ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("Invalid webhook URL")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        valid = (
            host and parsed.scheme in {"https", "http"}
            and (parsed.scheme == "https" or loopback)
            and parsed.username is None and parsed.password is None
            and "#" not in url and (port is None or port > 0)
        )
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("Webhook URL requires HTTPS (HTTP loopback allowed), without credentials or fragments")
    headers = webhook.get("headers", {})
    if not isinstance(headers, dict) or any(
        not isinstance(k, str) or not k or not isinstance(v, str)
        or not k.isascii() or not v.isascii()
        or any(c in k for c in "()<>@,;:\\ \"/[]?={}\t")
        or any(ord(c) < 32 or ord(c) == 127 for c in k + v)
        for k, v in headers.items()
    ):
        raise ValueError("Webhook headers must contain valid string names and values")
    required = {"jira": "project", "linear": "team_id"}.get(kind)
    if required and (not isinstance(webhook.get(required), str) or not webhook[required].strip()):
        raise ValueError(f"Webhook {kind} requires {required}")


def _payload(result, webhook):
    event = {key: result[key] for key in _FIELDS}
    event["path"] = event["path"].split("?", 1)[0].split("#", 1)[0]
    title = f'LedgerProbe {event["severity"].upper()}: {event["name"]}'
    description = (
        f'{event["rule_id"]}: {event["method"]} {event["path"]}\n'
        f'OWASP: {event["owasp_category"]}; CVSS: {event["cvss_score"]}'
    )
    kind = webhook["kind"]
    if kind in {"slack", "teams"}:
        return {"text": title + "\n" + description}
    if kind == "jira":
        return {"fields": {
            "project": {"key": webhook["project"]},
            "issuetype": {"name": "Task"},
            "summary": title,
            "description": {"type": "doc", "version": 1, "content": [{
                "type": "paragraph", "content": [{"type": "text", "text": description}],
            }]},
        }}
    if kind == "linear":
        return {"query": _LINEAR_MUTATION, "variables": {"input": {
            "teamId": webhook["team_id"], "title": title, "description": description,
        }}}
    return {"event": "ledgerprobe.finding", "result": event}


async def notify(results, webhooks, client) -> None:
    """Validate all destinations first, then POST each high/critical failure once.

    URLs are complete destination endpoints, including Jira's issue API or Linear's
    GraphQL endpoint. Non-2xx, transport, and GraphQL failures raise sanitized
    ValueErrors without response bodies, headers, or token-bearing URLs.
    """
    if not isinstance(webhooks, list):
        raise ValueError("Webhooks must be a list")
    for webhook in webhooks:
        _validate(webhook)
    findings = [r for r in results if r["status"] == "failed" and r["severity"] in {"high", "critical"}]
    for webhook in webhooks:
        for result in findings:
            payload = _payload(result, webhook)
            try:
                response = await client.post(webhook["url"], json=payload, headers=webhook.get("headers", {}))
            except Exception:
                raise ValueError("Webhook delivery failed") from None
            if not 200 <= response.status_code < 300:
                raise ValueError(f"Webhook delivery failed (HTTP {response.status_code})")
            if webhook["kind"] == "linear":
                try:
                    body = response.json()
                    success = not body.get("errors") and body["data"]["issueCreate"]["success"] is True
                except (ValueError, KeyError, TypeError, AttributeError):
                    success = False
                if not success:
                    raise ValueError("Linear issue creation failed")
