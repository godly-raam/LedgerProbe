"""Known-good/known-bad catalog for every finding the fuzzer can raise."""

from __future__ import annotations

OWASP_API1 = {"id": "API1:2023", "name": "Broken Object Level Authorization"}
OWASP_API2 = {"id": "API2:2023", "name": "Broken Authentication"}
OWASP_API6 = {"id": "API6:2023", "name": "Unrestricted Access to Sensitive Business Flows"}

CHECKS: dict[str, dict] = {
    "BOLA-ALLOWANCE-READ": {
        "title": "Cross-tenant allowance disclosure (BOLA)",
        "suite": "bola",
        "severity": "medium",
        "cvss": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
        "owasp": OWASP_API1,
        "cwe": "CWE-639",
        "description": "Parent A can read the allowance configuration of a teen in another family by supplying that teen's identifier.",
        "impact": "Discloses another household's spending limits and blocked merchant categories, enabling targeted policy-evasion attempts.",
        "endpoint": "GET /api/v1/family/allowance/{teen_id}",
        "remediation": {
            "summary": "Scope the lookup by both resource id and authenticated parent id, and return 404 when the pair does not match.",
            "language": "python",
            "vulnerable": (
                "teen = db.get(User, teen_id)\n"
                "allowance = db.get(Allowance, teen.id)\n"
                "return allowance  # authenticated parent never compared"
            ),
            "secure": (
                "teen = db.scalar(\n"
                "    select(User).where(\n"
                "        User.id == teen_id,\n"
                "        User.parent_id == parent.id,\n"
                "        User.role == \"teen\",\n"
                "    )\n"
                ")\n"
                "if teen is None:\n"
                "    raise HTTPException(404, \"teen not found in your family\")"
            ),
        },
    },
    "BOLA-ALLOWANCE-WRITE": {
        "title": "Cross-tenant allowance takeover (BOLA write)",
        "suite": "bola",
        "severity": "high",
        "cvss": {"score": 7.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"},
        "owasp": OWASP_API1,
        "cwe": "CWE-639",
        "description": "Parent A can rewrite another family's allowance and reassign it to their own parent id by calling the allowance endpoint with a foreign teen_id.",
        "impact": "An attacker-controlled guardian can lift spending limits and merchant-category blocks for any teen, defeating the core control of the neobank.",
        "endpoint": "POST /api/v1/family/allowance",
        "remediation": {
            "summary": "Never trust teen_id from the request body. Resolve the teen through a query constrained by parent_id before mutating anything.",
            "language": "python",
            "vulnerable": (
                "teen = _teen_or_404(db, payload.teen_id)\n"
                "allowance = db.get(Allowance, teen.id)\n"
                "allowance.daily_limit_cents = payload.daily_limit_cents\n"
                "allowance.blocked_mccs = json.dumps(payload.blocked_mccs)\n"
                "db.commit()"
            ),
            "secure": (
                "teen = db.scalar(\n"
                "    select(User)\n"
                "    .where(User.id == payload.teen_id)\n"
                "    .where(User.parent_id == parent.id)\n"
                "    .where(User.role == \"teen\")\n"
                ")\n"
                "if teen is None:\n"
                "    raise HTTPException(404, \"teen not found in your family\")\n"
                "allowance.daily_limit_cents = payload.daily_limit_cents"
            ),
        },
    },
    "BOLA-DEVICE-READ": {
        "title": "Cross-tenant SIM-binding disclosure",
        "suite": "bola",
        "severity": "medium",
        "cvss": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
        "owasp": OWASP_API1,
        "cwe": "CWE-639",
        "description": "A parent can read the SIM serial and attestation profile bound to another family's teen device.",
        "impact": "SIM serials and attestation strength are the exact inputs needed to social-engineer a carrier swap or forge a device assertion.",
        "endpoint": "GET /api/v1/device/{teen_id}",
        "remediation": {
            "summary": "Apply the same ownership predicate to device lookups and strip serial numbers from responses not needed by the client.",
            "language": "python",
            "vulnerable": (
                "device = db.get(Device, teen_id)\n"
                "return _device_payload(device)  # no family scoping"
            ),
            "secure": (
                "teen = db.scalar(\n"
                "    select(User).where(User.id == teen_id, User.parent_id == parent.id)\n"
                ")\n"
                "if teen is None:\n"
                "    raise HTTPException(404, \"teen not found in your family\")\n"
                "return _device_payload(db.get(Device, teen.id))"
            ),
        },
    },
    "BOLA-TRANSACTIONS-READ": {
        "title": "Cross-tenant transaction history disclosure",
        "suite": "bola",
        "severity": "medium",
        "cvss": {"score": 6.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
        "owasp": OWASP_API1,
        "cwe": "CWE-639",
        "description": "Parent A can list the payment history of another family's teen.",
        "impact": "Exposes merchant names, amounts and MCCs of minors outside the authenticated household.",
        "endpoint": "GET /api/v1/wallet/transactions/{teen_id}",
        "remediation": {
            "summary": "Derive the teen id from the authenticated relationship instead of the path, or validate parent ownership first.",
            "language": "python",
            "vulnerable": (
                "rows = db.scalars(\n"
                "    select(Payment).where(Payment.teen_id == path_teen_id)\n"
                ").all()\n"
                "return {\"transactions\": rows}"
            ),
            "secure": (
                "teen = db.scalar(\n"
                "    select(User).where(User.id == teen_id, User.parent_id == parent.id)\n"
                ")\n"
                "if teen is None:\n"
                "    raise HTTPException(404, \"teen not found in your family\")\n"
                "rows = db.scalars(\n"
                "    select(Payment).where(Payment.teen_id == teen.id)\n"
                ").all()"
            ),
        },
    },
    "MCC-ARRAY-BYPASS": {
        "title": "Merchant category block bypass via MCC array smuggling",
        "suite": "mcc",
        "severity": "high",
        "cvss": {"score": 7.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"},
        "owasp": OWASP_API6,
        "cwe": "CWE-863",
        "description": "The payment endpoint checks the first MCC in a supplied list but books the last one, so a blocked category can be disguised as an allowed one.",
        "impact": "A teen can spend against a parent-blocked category (for example gambling, MCC 7995) while the authorization decision sees grocery (5411).",
        "endpoint": "POST /api/v1/wallet/pay",
        "remediation": {
            "summary": "Reject list values for a scalar field, normalize once, and authorize the exact MCC that will be persisted.",
            "language": "python",
            "vulnerable": (
                "if isinstance(payload.mcc, list):\n"
                "    check_mcc = payload.mcc[0]\n"
                "    booked_mcc = payload.mcc[-1]\n"
                "if check_mcc in blocked:\n"
                "    raise HTTPException(403)\n"
                "payment = Payment(mcc=booked_mcc, ...)"
            ),
            "secure": (
                "mcc = payload.mcc.strip()\n"
                "if mcc not in KNOWN_MCCS:\n"
                "    raise HTTPException(422, \"unknown mcc\")\n"
                "if mcc in blocked_categories(allowance):\n"
                "    raise HTTPException(403, \"merchant category blocked\")\n"
                "payment = Payment(mcc=mcc, ...)"
            ),
        },
    },
    "MCC-NOT-ENFORCED": {
        "title": "Family MCC block accepted a blocked payment",
        "suite": "mcc",
        "severity": "high",
        "cvss": {"score": 7.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"},
        "owasp": OWASP_API6,
        "cwe": "CWE-863",
        "description": "A direct payment using an MCC on the family blocklist was approved.",
        "impact": "The merchant-category restriction advertised to parents is not enforced at all, allowing unrestricted spending.",
        "endpoint": "POST /api/v1/wallet/pay",
        "remediation": {
            "summary": "Look up the category server-side from a trusted MCC registry and compare it to the policy before any balance mutation.",
            "language": "python",
            "vulnerable": (
                "if check_mcc in blocked:\n"
                "    raise HTTPException(403)\n"
                "# check uses a different value than the one booked"
            ),
            "secure": (
                "category = MCC_REGISTRY.lookup(booked_mcc)\n"
                "if category in blocked_categories(allowance):\n"
                "    raise HTTPException(403, \"merchant category blocked\")"
            ),
        },
    },
    "RACE-LIMIT-BYPASS": {
        "title": "Concurrent payments bypass daily limit and lose balance updates",
        "suite": "race",
        "severity": "high",
        "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"},
        "owasp": OWASP_API6,
        "cwe": "CWE-362",
        "description": "Balance and spend-limit checks are separated from their writes by an await, so simultaneous payments all observe the same stale state and overwrite each other's deductions.",
        "impact": "A teen can approve more payments than the daily allowance allows, spend the balance multiple times, and move the ledger out of sync with the wallet.",
        "endpoint": "POST /api/v1/wallet/pay",
        "remediation": {
            "summary": "Make each invariant a single conditional UPDATE in one transaction, or lock the wallet row (SELECT ... FOR UPDATE) before reading it.",
            "language": "python",
            "vulnerable": (
                "balance = wallet.balance_cents\n"
                "if balance < amount:\n"
                "    raise HTTPException(402)\n"
                "await asyncio.sleep(RACE_WINDOW)\n"
                "wallet.balance_cents = balance - amount\n"
                "db.commit()"
            ),
            "secure": (
                "spend_ok = db.execute(\n"
                "    update(Allowance)\n"
                "    .where(Allowance.teen_id == teen.id)\n"
                "    .where(Allowance.spent_today_cents + amount <= Allowance.daily_limit_cents)\n"
                "    .values(spent_today_cents=Allowance.spent_today_cents + amount)\n"
                ")\n"
                "if spend_ok.rowcount != 1:\n"
                "    db.rollback()\n"
                "    raise HTTPException(403, \"daily limit exceeded\")\n"
                "balance_ok = db.execute(\n"
                "    update(Wallet)\n"
                "    .where(Wallet.teen_id == teen.id, Wallet.balance_cents >= amount)\n"
                "    .values(balance_cents=Wallet.balance_cents - amount)\n"
                ")"
            ),
        },
    },
}


def make_finding(check_id: str, evidence: dict, notes: str | None = None) -> dict:
    spec = CHECKS[check_id]
    finding = {
        "check_id": check_id,
        "title": spec["title"],
        "suite": spec["suite"],
        "severity": spec["severity"],
        "cvss": spec["cvss"],
        "owasp": spec["owasp"],
        "cwe": spec["cwe"],
        "endpoint": spec["endpoint"],
        "description": spec["description"],
        "impact": spec["impact"],
        "evidence": {**evidence, "notes": notes} if notes else evidence,
        "remediation": spec["remediation"],
    }
    return finding
