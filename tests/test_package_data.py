"""Installed-package data checks for the runtime JSON schemas."""

import json
from importlib.metadata import distribution
from importlib.resources import files

from pkg.dojo import write_export


def test_schema_resources_are_packaged():
    for name in ("results.schema.json", "defectdojo.generic.schema.json"):
        schema = json.loads(files("schemas").joinpath(name).read_text(encoding="utf-8"))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_schema_resources_are_in_installed_distribution():
    entries = {str(entry) for entry in (distribution("ledgerprobe").files or [])}
    assert "schemas/results.schema.json" in entries
    assert "schemas/defectdojo.generic.schema.json" in entries


def test_dojo_export_uses_packaged_schema(tmp_path):
    output = write_export(
        [{
            "status": "failed",
            "rule_id": "ownership",
            "method": "GET",
            "path_template": "/objects/{id}",
            "path": "/objects/1",
            "check_type": "bola",
            "cwe": 639,
        }],
        tmp_path / "dojo.json",
        target="https://target.test",
    )
    assert json.loads(output.read_text(encoding="utf-8"))[0]["vuln_id_from_tool"] == "ownership"
