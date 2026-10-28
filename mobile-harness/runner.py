#!/usr/bin/env python3
"""FinShield-Core mobile attestation and SIM-binding inspector.

Two modes:
  --serial <adb-serial>  attach Frida to a running app and infer the surface
  --simulate             score a deterministic profile (no device required)

The score only uses controls that were actually observed. In device mode,
server-side attestation verification cannot be seen from the client, so that
control is reported as NOT_OBSERVED instead of being guessed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
HOOK_SCRIPT = HERE / "scripts" / "sim_hook.js"

PROFILES: dict[str, dict] = {
    "vulnerable": {
        "strongbox_backed": False,
        "attestation_verified": False,
        "sim_binding_uses_strongbox_key": False,
        "root_detection_present": False,
        "sms_forwarding_suspected": False,
        "sim_serial_read": True,
        "subscriber_id_read": True,
        "build_tags": "test-keys",
        "notes": [
            "TelephonyManager.getSimSerialNumber is used as the binding factor.",
            "Key material lives in a software keystore with no StrongBox request.",
            "The app trusts a client-supplied attestation boolean.",
        ],
    },
    "hardened": {
        "strongbox_backed": True,
        "attestation_verified": True,
        "sim_binding_uses_strongbox_key": True,
        "root_detection_present": True,
        "sms_forwarding_suspected": False,
        "sim_serial_read": False,
        "subscriber_id_read": False,
        "build_tags": "release-keys",
        "notes": [
            "SIM binding is derived from a StrongBox-backed key pair.",
            "Hardware key attestation is validated against a server nonce.",
            "Root and hook telemetry is evaluated server-side.",
        ],
    },
}

FINDINGS = {
    "AUTH-STRONGBOX": {
        "title": "Key material is not isolated in StrongBox/TEE",
        "severity": "medium",
        "cvss": {"score": 5.5, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
        "owasp": {"id": "M10:2024", "name": "Insufficient Cryptography"},
        "masvs": "MASVS-CRYPTO-1",
        "cwe": "CWE-320",
        "description": "The app does not require hardware-backed key generation, so extracted key material can be used to impersonate the device.",
        "impact": "A cloned or rooted device can sign attestation and payment requests without physical StrongBox isolation.",
        "remediation": {
            "summary": "Generate binding keys with setIsStrongBoxBacked(true), fall back only to TEE, and refuse software-only providers.",
            "language": "kotlin",
            "vulnerable": (
                "val key = KeyGenerator.getInstance(\"AES\").apply {\n"
                "    init(256)\n"
                "}.generateKey()  // default provider, exportable in software"
            ),
            "secure": (
                "val spec = KeyGenParameterSpec.Builder(ALIAS, PURPOSE_SIGN)\n"
                "    .setIsStrongBoxBacked(true)   // require hardware isolation\n"
                "    .setUserAuthenticationRequired(true)\n"
                "    .build()\n"
                "keyGenerator.init(spec)"
            ),
        },
    },
    "AUTH-ATTESTATION": {
        "title": "Device attestation is trusted without server verification",
        "severity": "high",
        "cvss": {"score": 7.7, "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "owasp": {"id": "M3:2024", "name": "Insecure Authentication/Authorization"},
        "masvs": "MASVS-AUTH-1",
        "cwe": "CWE-345",
        "description": "The client decides whether attestation passed, or a key attestation certificate chain is never validated against a server nonce.",
        "impact": "A modified client or emulator can assert 'hardware verified' and bind an attacker-controlled SIM to the account.",
        "remediation": {
            "summary": "Send the attestation certificate chain and nonce to the backend; verify the chain, challenge, and device integrity there.",
            "language": "kotlin",
            "vulnerable": (
                "val result = attestationClient.isDeviceTrusted()\n"
                "if (result) bindSim()  // client-controlled boolean"
            ),
            "secure": (
                "val chain = keyStore.getCertificateChain(ALIAS)\n"
                "api.verifyAttestation(chain, challengeFromServer)\n"
                "    .onSuccess { bindSim() }  // server owns the decision"
            ),
        },
    },
    "AUTH-SIM-BINDING": {
        "title": "SIM binding relies on spoofable telephony identifiers",
        "severity": "high",
        "cvss": {"score": 7.7, "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
        "owasp": {"id": "M3:2024", "name": "Insecure Authentication/Authorization"},
        "masvs": "MASVS-AUTH-1",
        "cwe": "CWE-287",
        "description": "The binding decision uses TelephonyManager SIM serial/subscriber values, which are readable, mutable on rooted devices, and available to Frida hooks.",
        "impact": "A SIM swap or runtime hook can rebind the wallet without possessing the original hardware key.",
        "remediation": {
            "summary": "Bind to a StrongBox key pair certified by the backend, not to a SIM serial. Treat telephony data as supplementary risk signal only.",
            "language": "kotlin",
            "vulnerable": (
                "val bindingId = telephonyManager.simSerialNumber\n"
                "api.bindDevice(bindingId)  // value attacker can set"
            ),
            "secure": (
                "val bindingId = keyStore.getCertificate(ALIAS)\n"
                "    .publicKey.encoded.toHex()\n"
                "api.bindDevice(\n"
                "    bindingId = bindingId,\n"
                "    attestation = keyAttestationChain,\n"
                "    nonce = serverNonce,\n"
                ")"
            ),
        },
    },
    "RES-ROOT-DETECTION": {
        "title": "No effective tamper or root detection",
        "severity": "medium",
        "cvss": {"score": 6.1, "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"},
        "owasp": {"id": "M7:2024", "name": "Insufficient Binary Protections"},
        "masvs": "MASVS-RESILIENCE-1",
        "cwe": "CWE-693",
        "description": "The app does not act on build-tag, root, or runtime-hook telemetry, leaving Frida instrumentation undetected.",
        "impact": "An attacker can hook SIM and attestation routines at runtime, observe secrets, and drive the UI through a tampered client.",
        "remediation": {
            "summary": "Combine Play Integrity verdicts, build-tag checks, and runtime instrumentation signals, and enforce the decision on the server.",
            "language": "kotlin",
            "vulnerable": (
                "if (Build.TAGS == \"test-keys\") {\n"
                "    Log.w(TAG, \"debug build\")\n"
                "}  // warning only, flow continues"
            ),
            "secure": (
                "val verdict = integrityClient.requestIntegrityToken(nonce)\n"
                "if (!verdict.isDeviceIntegrity()) {\n"
                "    securityEvents.report(\"tampered_device\")\n"
                "    server.revokeSession()\n"
                "}"
            ),
        },
    },
    "AUTH-SMS-FORWARDING": {
        "title": "SMS forwarding indicators observed during payment flow",
        "severity": "high",
        "cvss": {"score": 6.5, "vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "owasp": {"id": "M3:2024", "name": "Insecure Authentication/Authorization"},
        "masvs": "MASVS-AUTH-1",
        "cwe": "CWE-287",
        "description": "Outbound SMS activity was observed from the banking process, consistent with OTP interception or forwarding malware.",
        "impact": "One-time codes used for step-up authentication can be exfiltrated and replayed by an attacker.",
        "remediation": {
            "summary": "Move OTP delivery to app-bound push or passkeys, and block bindings from sessions showing SMS interception signals.",
            "language": "kotlin",
            "vulnerable": (
                "val otp = smsRetriever.awaitSms()\n"
                "api.rebindSim(otp)  // SMS is the only possession factor"
            ),
            "secure": (
                "val credential = createPublicKeyCredential(\n"
                "    challenge = serverChallenge,\n"
                "    userVerification = REQUIRED,\n"
                ")\n"
                "api.rebindSim(attestation = credential.attestationObject)"
            ),
        },
    },
}

# (control id, surface key, expected value, points, finding id)
CONTROLS = [
    ("hardware-keystore", "strongbox_backed", True, 25, "AUTH-STRONGBOX"),
    ("attestation-verified", "attestation_verified", True, 30, "AUTH-ATTESTATION"),
    ("hardware-key-binding", "sim_binding_uses_strongbox_key", True, 25, "AUTH-SIM-BINDING"),
    ("tamper-detection", "root_detection_present", True, 10, "RES-ROOT-DETECTION"),
    ("no-sms-forwarding", "sms_forwarding_suspected", False, 10, "AUTH-SMS-FORWARDING"),
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def score_surface(surface: dict, mode: str, profile: str | None, telemetry: dict | None = None) -> dict:
    """Turn observed signals into controls, findings, and a 0-100 score."""
    controls = []
    findings = []
    earned = 0
    possible = 0
    seen_findings: set[str] = set()

    for control_id, key, expected, points, finding_key in CONTROLS:
        observed = surface.get(key) is not None
        passed = observed and surface.get(key) == expected
        controls.append(
            {
                "id": control_id,
                "label": control_id.replace("-", " "),
                "points": points,
                "earned": points if passed else 0,
                "passed": passed,
                "observed": observed,
                "expected": expected,
                "actual": surface.get(key),
            }
        )
        if observed:
            possible += points
            if passed:
                earned += points
        if observed and not passed and finding_key not in seen_findings:
            seen_findings.add(finding_key)
            spec = FINDINGS[finding_key]
            findings.append(
                {
                    "id": f"MSH-{len(findings) + 1:03d}",
                    "check_id": finding_key,
                    "title": spec["title"],
                    "severity": spec["severity"],
                    "cvss": spec["cvss"],
                    "owasp": spec["owasp"],
                    "masvs": spec["masvs"],
                    "cwe": spec["cwe"],
                    "description": spec["description"],
                    "impact": spec["impact"],
                    "remediation": spec["remediation"],
                    "evidence": {"surface": surface},
                }
            )

    score = round(earned / possible * 100) if possible else 0
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "E" if score >= 40 else "F"
    resilience = "strong" if score >= 75 else "moderate" if score >= 40 else "weak"

    return {
        "schema_version": "1.0",
        "run": {
            "id": utcnow().strftime("MSH-%Y%m%d-%H%M%S")
            + f"-{mode}"
            + (f"-{profile}" if profile else ""),
            "mode": mode,
            "profile": profile,
            "score": score,
            "grade": grade,
            "resilience": resilience,
            "confidence": "simulated" if mode == "simulate" else "inferred",
            "controls_observed": sum(1 for control in controls if control["observed"]),
            "controls_total": len(controls),
        },
        "surface": surface,
        "controls": controls,
        "findings": findings,
        "telemetry": telemetry or {},
    }


def _adb(serial: str, *args: str) -> dict:
    command = ["adb", "-s", serial, "shell", *args]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        return {"command": " ".join(command), "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip()}
    except (subprocess.TimeoutExpired, FileNotFoundError) as error:
        return {"command": " ".join(command), "error": str(error)}


def collect_device(serial: str, package: str, duration: float) -> tuple[dict, dict]:
    """Attach Frida, collect telemetry, and infer only observable signals."""
    if shutil.which("adb") is None:
        raise RuntimeError("adb not found on PATH")
    try:
        import frida  # imported lazily so simulate mode needs no frida install
    except ImportError as error:
        raise RuntimeError("frida-python is required for device mode: pip install -r requirements.txt") from error

    surface: dict = {
        "strongbox_backed": None,
        "attestation_verified": None,  # cannot be observed client-side
        "sim_binding_uses_strongbox_key": None,
        "root_detection_present": None,
        "sms_forwarding_suspected": None,
        "sim_serial_read": False,
        "subscriber_id_read": False,
    }
    telemetry: dict = {"adb": {}, "events": [], "notes": []}
    telemetry["adb"]["build_tags"] = _adb(serial, "getprop", "ro.build.tags")
    telemetry["adb"]["model"] = _adb(serial, "getprop", "ro.product.model")
    telemetry["adb"]["package"] = _adb(serial, "pm", "list", "packages", package)

    device = frida.get_usb_device(timeout=5)
    process = next((item for item in device.enumerate_processes() if item.name == package), None)
    if process is None:
        raise RuntimeError(f"{package} is not running on {serial}; start the app first")

    telemetry["events"].append({"type": "attach", "signal": "process", "value": process.pid})
    session = device.attach(process.pid)
    script = session.create_script(HOOK_SCRIPT.read_text(encoding="utf-8"))

    def on_message(message, _data):
        if message.get("type") == "send":
            telemetry["events"].append(message["payload"])
        elif message.get("type") == "error":
            telemetry["events"].append({"type": "frida_error", "value": message.get("description")})

    script.on("message", on_message)
    script.load()
    time.sleep(duration)
    try:
        script.unload()
    finally:
        session.detach()

    for event in telemetry["events"]:
        signal = event.get("signal")
        value = str(event.get("value", "")).lower()
        if event.get("type") == "telephony":
            if signal == "sim_serial_read":
                surface["sim_serial_read"] = True
            if signal == "subscriber_id_read":
                surface["subscriber_id_read"] = True
        elif event.get("type") == "keystore" and signal == "strongbox_requested":
            surface["strongbox_backed"] = value == "true"
        elif event.get("type") == "sms" and signal == "outbound_sms":
            surface["sms_forwarding_suspected"] = True

    if surface["sim_serial_read"] or surface["subscriber_id_read"]:
        surface["sim_binding_uses_strongbox_key"] = False
    telemetry["notes"].extend(
        [
            "attestation_verified is NOT_OBSERVED: certificate-chain validation happens server-side.",
            "root_detection_present is NOT_OBSERVED: Frida telemetry cannot prove enforcement.",
            "Scores exclude unobserved controls instead of assuming they pass.",
        ]
    )
    return surface, telemetry


def main() -> int:
    parser = argparse.ArgumentParser(description="FinShield-Core mobile attestation inspector")
    parser.add_argument("--serial", help="ADB serial for device mode")
    parser.add_argument("--package", default="com.finshield.mockbank", help="target package")
    parser.add_argument("--simulate", action="store_true", help="score a deterministic profile")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="vulnerable")
    parser.add_argument("--duration", type=float, default=6.0, help="seconds of Frida telemetry")
    parser.add_argument("--out", default=str(HERE / "reports"), help="report output directory")
    args = parser.parse_args()

    started = utcnow()
    try:
        if args.serial:
            surface, telemetry = collect_device(args.serial, args.package, args.duration)
            mode, profile = "device", None
        else:
            surface = dict(PROFILES[args.profile])
            profile = args.profile
            mode = "simulate"
            telemetry = {
                "notes": surface.pop("notes", []),
                "events": [{"type": "simulation", "signal": "profile", "value": profile}],
            }
    except RuntimeError as error:
        print(f"error: {error}")
        return 1

    report = score_surface(surface, mode=mode, profile=profile, telemetry=telemetry)
    report["run"].update(
        {
            "started_at": started.isoformat(),
            "finished_at": utcnow().isoformat(),
            "package": args.package,
            "serial": args.serial,
        }
    )
    report["telemetry"] = telemetry

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"mobile-{report['run']['id']}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    run = report["run"]
    print(f"[+] {run['id']}  resilience {run['score']}/100 ({run['resilience']}, grade {run['grade']})")
    if run["mode"] == "simulate":
        print(f"    simulated profile: {run['profile']}")
    for finding in report["findings"]:
        print(f"    {finding['id']}  {finding['severity'].upper():<8} {finding['title']}")
    print(f"[+] report written to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
