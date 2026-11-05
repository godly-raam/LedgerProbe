import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from pkg.dojo import build_export, write_export


def finding(rule_id="bola-owner", path="/objects/{id}", status="failed"):
    return {"status": status, "rule_id": rule_id, "name": "Do not export this evidence marker",
            "method": "GET", "path_template": path, "path": "/objects/UNIQUE-EXPANDED-ID-7391528",
            "cvss_score": 8.1, "check_type": "bola", "remediation": "Enforce ownership.",
            "message": "UNIQUE-EVIDENCE-7391528", "cwe": 639,
            "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L", "rating": "high"}}


def test_generic_export_is_schema_valid_stable_and_value_free(tmp_path):
    rows = [finding(), finding("unauth", "/public/{id}")]
    payload = build_export(rows, target="https://target.example.test")
    schema = json.loads((Path(__file__).parents[1] / "schemas/defectdojo.generic.schema.json").read_text())
    jsonschema.Draft202012Validator(schema).validate(payload)
    assert len(payload) == 2
    assert payload[0]["cwe"] == 639 and payload[1]["cwe"] == 639
    assert "UNIQUE-EVIDENCE-7391528" not in json.dumps(payload)
    assert "UNIQUE-EXPANDED-ID-7391528" not in json.dumps(payload)
    assert payload[0]["endpoints"] == ["/objects/{id}"]
    assert payload[0]["unique_id_from_tool"] == build_export([finding()], target="https://other.test")[0]["unique_id_from_tool"]
    output = tmp_path / "dojo.json"
    write_export(rows, output, target="https://target.example.test")
    assert json.loads(output.read_text()) == payload


def test_suppressed_is_inactive_and_non_findings_are_omitted():
    payload = build_export([finding(status="suppressed"), finding(status="inconclusive"), finding(status="error")],
                           target="https://target.test")
    assert len(payload) == 1
    assert payload[0]["active"] is False and payload[0]["false_p"] is True
