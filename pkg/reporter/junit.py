"""JUnit XML output; every check contributes exactly one test case."""

from pathlib import Path
import json
import re
from xml.etree import ElementTree as ET

from ._evidence import result_properties


_INVALID_XML = re.compile("[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def _text(value):
    return _INVALID_XML.sub("\ufffd", value)


def write_junit(results, path) -> Path:
    results = list(results)
    suite = ET.Element("testsuite", {
        "name": "LedgerProbe", "tests": str(len(results)),
        "failures": str(sum(r["status"] == "failed" for r in results)),
        "errors": str(sum(r["status"] == "error" for r in results)),
        "skipped": str(sum(r["status"] in {"skipped", "inconclusive"} for r in results)),
    })
    for result in results:
        case = ET.SubElement(suite, "testcase", {
            "classname": _text(result["rule_id"]),
            "name": _text(f'{result["name"]} [{result["method"]} {result["path"]}]'),
        })
        tag = {"failed": "failure", "error": "error", "skipped": "skipped", "inconclusive": "skipped"}.get(result["status"])
        if tag:
            message = result["message"]
            if result["status"] == "inconclusive" and result.get("reason"):
                message = f"{message}: {result['reason']}" if message else result["reason"]
            message = _text(message)
            ET.SubElement(case, tag, {"message": message}).text = message
        if properties := result_properties(result):
            node = ET.SubElement(case, "properties")
            for name, value in properties.items():
                encoded = json.dumps(value, sort_keys=True) if not isinstance(value, str) else value
                ET.SubElement(node, "property", {"name": "ledgerprobe." + name, "value": _text(encoded)})
    path = Path(path)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
    return path
