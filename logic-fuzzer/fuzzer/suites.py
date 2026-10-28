from __future__ import annotations

import asyncio
from collections import Counter

from .api import BankAPI
from .checks import make_finding

PARENT_A = "parent.a@finshield.dev"
TEEN_A = "teen.a@finshield.dev"
TEEN_B = "teen.b@finshield.dev"


def _blocked(status: int) -> bool:
    return status in (400, 401, 403, 404, 409, 422)


def _check(name: str, suite: str, passed: bool, detail: str) -> dict:
    return {"name": name, "suite": suite, "passed": passed, "detail": detail}


async def run_bola(api: BankAPI) -> dict:
    """Parent A tries to reach Teen B's objects. Any 2xx is a finding."""
    await api.reset()
    parent = await api.login(PARENT_A)
    teen_b = await api.login(TEEN_B)

    findings: list[dict] = []
    checks: list[dict] = []
    edges: list[dict] = []
    nodes = [
        {"id": "parent_a", "label": "Parent A", "kind": "principal"},
        {"id": "parent_b", "label": "Parent B", "kind": "principal"},
        {"id": "teen_a", "label": "Teen A", "kind": "teen"},
        {"id": "teen_b", "label": "Teen B", "kind": "teen"},
        {"id": "allowance_a", "label": "Teen A allowance", "kind": "resource"},
        {"id": "allowance_b", "label": "Teen B allowance", "kind": "resource"},
        {"id": "device_b", "label": "Teen B SIM binding", "kind": "resource"},
        {"id": "transactions_b", "label": "Teen B transactions", "kind": "resource"},
    ]

    own = await api.call("GET", "/api/v1/family/allowance/usr_teen_a", token=parent.token)
    own_ok = own["response"]["status"] == 200
    checks.append(
        _check(
            "bola.control.parent_reads_own_teen",
            "bola",
            own_ok,
            f"own allowance lookup returned {own['response']['status']}",
        )
    )
    edges.append(
        {
            "id": "e-own-allowance",
            "from": "parent_a",
            "to": "allowance_a",
            "action": "read",
            "allowed": own_ok,
            "check_id": None,
            "finding_id": None,
        }
    )

    read = await api.call("GET", "/api/v1/family/allowance/usr_teen_b", token=parent.token)
    read_hit = read["response"]["status"] == 200
    if read_hit:
        findings.append(
            make_finding(
                "BOLA-ALLOWANCE-READ",
                read,
                notes=f"Parent A read allowance owned by {teen_b.id} ({teen_b.user['parent_id']})",
            )
        )
    checks.append(
        _check(
            "bola.allowance.read",
            "bola",
            not read_hit,
            f"cross-family read returned {read['response']['status']}",
        )
    )
    edges.append(
        {
            "id": "e-read-allowance-b",
            "from": "parent_a",
            "to": "allowance_b",
            "action": "read",
            "allowed": read_hit,
            "check_id": "BOLA-ALLOWANCE-READ" if read_hit else None,
            "finding_id": None,
        }
    )

    write_payload = {"teen_id": "usr_teen_b", "daily_limit_cents": 999999, "blocked_mccs": []}
    write = await api.call(
        "POST", "/api/v1/family/allowance", token=parent.token, payload=write_payload
    )
    write_hit = write["response"]["status"] == 200
    if write_hit:
        findings.append(
            make_finding(
                "BOLA-ALLOWANCE-WRITE",
                write,
                notes="Parent A set Teen B's limit to 999999 cents and cleared the MCC blocklist.",
            )
        )
    checks.append(
        _check(
            "bola.allowance.write",
            "bola",
            not write_hit,
            f"cross-family write returned {write['response']['status']}",
        )
    )
    edges.append(
        {
            "id": "e-write-allowance-b",
            "from": "parent_a",
            "to": "allowance_b",
            "action": "write",
            "allowed": write_hit,
            "check_id": "BOLA-ALLOWANCE-WRITE" if write_hit else None,
            "finding_id": None,
        }
    )

    device = await api.call("GET", "/api/v1/device/usr_teen_b", token=parent.token)
    device_hit = device["response"]["status"] == 200
    if device_hit:
        findings.append(
            make_finding(
                "BOLA-DEVICE-READ",
                device,
                notes="Response includes the SIM serial and attestation profile for Teen B.",
            )
        )
    checks.append(
        _check(
            "bola.device.read",
            "bola",
            not device_hit,
            f"cross-family device read returned {device['response']['status']}",
        )
    )
    edges.append(
        {
            "id": "e-read-device-b",
            "from": "parent_a",
            "to": "device_b",
            "action": "read",
            "allowed": device_hit,
            "check_id": "BOLA-DEVICE-READ" if device_hit else None,
            "finding_id": None,
        }
    )

    txns = await api.call("GET", "/api/v1/wallet/transactions/usr_teen_b", token=parent.token)
    txns_hit = txns["response"]["status"] == 200
    if txns_hit:
        findings.append(
            make_finding(
                "BOLA-TRANSACTIONS-READ",
                txns,
                notes="Parent A listed another household's transaction history.",
            )
        )
    checks.append(
        _check(
            "bola.transactions.read",
            "bola",
            not txns_hit,
            f"cross-family transactions read returned {txns['response']['status']}",
        )
    )
    edges.append(
        {
            "id": "e-read-transactions-b",
            "from": "parent_a",
            "to": "transactions_b",
            "action": "read",
            "allowed": txns_hit,
            "check_id": "BOLA-TRANSACTIONS-READ" if txns_hit else None,
            "finding_id": None,
        }
    )

    return {"findings": findings, "checks": checks, "graph": {"nodes": nodes, "edges": edges}}


async def run_mcc(api: BankAPI) -> dict:
    """Teen A is blocked from MCC 7995 (gambling) by family policy."""
    await api.reset()
    teen = await api.login(TEEN_A)
    findings: list[dict] = []
    checks: list[dict] = []

    baseline = await api.call(
        "POST",
        "/api/v1/wallet/pay",
        token=teen.token,
        payload={"amount_cents": 100, "mcc": "7995", "merchant": "Lucky Spin"},
    )
    baseline_blocked = _blocked(baseline["response"]["status"])
    if not baseline_blocked:
        findings.append(
            make_finding(
                "MCC-NOT-ENFORCED",
                baseline,
                notes="A direct payment with the blocked MCC was accepted.",
            )
        )
    checks.append(
        _check(
            "mcc.blocked_direct",
            "mcc",
            baseline_blocked,
            f"blocked MCC payment returned {baseline['response']['status']}",
        )
    )

    control = await api.call(
        "POST",
        "/api/v1/wallet/pay",
        token=teen.token,
        payload={"amount_cents": 25, "mcc": "5411", "merchant": "Corner Grocer"},
    )
    control_ok = control["response"]["status"] == 200
    checks.append(
        _check(
            "mcc.allowed_control",
            "mcc",
            control_ok,
            f"allowed grocery payment returned {control['response']['status']}",
        )
    )

    smuggled = await api.call(
        "POST",
        "/api/v1/wallet/pay",
        token=teen.token,
        payload={"amount_cents": 100, "mcc": ["5411", "7995"], "merchant": "Loop Hole"},
    )
    smuggled_hit = (
        smuggled["response"]["status"] == 200
        and isinstance(smuggled["response"]["body"], dict)
        and smuggled["response"]["body"].get("mcc") == "7995"
    )
    if smuggled_hit:
        findings.append(
            make_finding(
                "MCC-ARRAY-BYPASS",
                smuggled,
                notes="Policy evaluated mcc[0]=5411 (grocery) but booked mcc[-1]=7995 (gambling).",
            )
        )
    checks.append(
        _check(
            "mcc.array_smuggling",
            "mcc",
            not smuggled_hit,
            f"array-wrapped MCC payment returned {smuggled['response']['status']}",
        )
    )

    return {"findings": findings, "checks": checks, "graph": {"nodes": [], "edges": []}}


async def run_race(api: BankAPI, attempts: int = 12, amount_cents: int = 3000) -> dict:
    """Fire N payments in one burst and compare ledger against wallet state."""
    await api.reset()
    teen = await api.login(TEEN_A)

    balance_before = await api.call("GET", "/api/v1/wallet/balance", token=teen.token)
    allowance_before = await api.call("GET", "/api/v1/family/allowance/usr_teen_a", token=teen.token)
    starting_balance = balance_before["response"]["body"]["balance_cents"]
    daily_limit = allowance_before["response"]["body"]["daily_limit_cents"]

    barrier = asyncio.Barrier(attempts)

    async def one_payment(index: int) -> dict:
        await barrier.wait()
        return await api.call(
            "POST",
            "/api/v1/wallet/pay",
            token=teen.token,
            payload={
                "amount_cents": amount_cents,
                "mcc": "5411",
                "merchant": f"RaceMart #{index + 1}",
            },
        )

    results = await asyncio.gather(*(one_payment(index) for index in range(attempts)))
    statuses = Counter(result["response"]["status"] for result in results)
    approved = [result for result in results if result["response"]["status"] == 200]
    approved_total = sum(result["response"]["body"].get("amount_cents", amount_cents) for result in approved)

    balance_after = await api.call("GET", "/api/v1/wallet/balance", token=teen.token)
    txns_after = await api.call("GET", "/api/v1/wallet/transactions/usr_teen_a", token=teen.token)
    ending_balance = balance_after["response"]["body"]["balance_cents"]
    max_allowed = daily_limit // amount_cents
    ledger_delta = starting_balance - ending_balance
    consistent = ledger_delta == approved_total

    burst = {
        "attempts": attempts,
        "amount_cents": amount_cents,
        "daily_limit_cents": daily_limit,
        "status_counts": {str(k): v for k, v in sorted(statuses.items())},
        "approved": len(approved),
        "safe_max_approved": max_allowed,
        "approved_total_cents": approved_total,
        "starting_balance_cents": starting_balance,
        "ending_balance_cents": ending_balance,
        "ledger_delta_cents": ledger_delta,
        "balance_consistent": consistent,
        "transactions_recorded": txns_after["response"]["body"].get("count", 0),
    }

    checks = [
        _check(
            "race.daily_limit",
            "race",
            len(approved) <= max_allowed,
            f"{len(approved)} of {attempts} payments approved; limit allowed {max_allowed}",
        ),
        _check(
            "race.balance_integrity",
            "race",
            consistent,
            f"wallet debited {ledger_delta} cents for {approved_total} cents of approved payments",
        ),
    ]

    findings: list[dict] = []
    if len(approved) > max_allowed or not consistent:
        first = approved[0] if approved else results[0]
        evidence = {
            **first,
            "burst": burst,
        }
        findings.append(
            make_finding(
                "RACE-LIMIT-BYPASS",
                evidence,
                notes=(
                    f"{len(approved)}/{attempts} concurrent payments approved "
                    f"(safe maximum {max_allowed}); wallet moved by {ledger_delta} cents "
                    f"for {approved_total} cents of approved volume."
                ),
            )
        )

    return {"findings": findings, "checks": checks, "graph": {"nodes": [], "edges": []}}
