"""JUnit XML output; every check contributes exactly one test case."""

from pathlib import Path
import re
from xml.etree import ElementTree as ET


_INVALID_XML = re.compile("[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def _text(value):
    return _INVALID_XML.sub("\ufffd", value)


def write_junit(results, path) -> Path:
    results = list(results)
    suite = ET.Element("testsuite", {
        "name": "LedgerProbe", "tests": str(len(results)),
        "failures": str(sum(r["status"] == "failed" for r in results)),
        "errors": str(sum(r["status"] == "error" for r in results)),
        "skipped": str(sum(r["status"] == "skipped" for r in results)),
    })
    for result in results:
        case = ET.SubElement(suite, "testcase", {
            "classname": _text(result["rule_id"]),
            "name": _text(f'{result["name"]} [{result["method"]} {result["path"]}]'),
        })
        tag = {"failed": "failure", "error": "error", "skipped": "skipped"}.get(result["status"])
        if tag:
            message = _text(result["message"])
            ET.SubElement(case, tag, {"message": message}).text = message
    path = Path(path)
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)
    return path
