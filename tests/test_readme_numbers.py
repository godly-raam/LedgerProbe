"""Keep the README At a glance counts tied to the recorded result files.

Every number in that block must be derivable from a committed results record:
`benchmark/results_v1.md` and `benchmark/RESULTS.md` for the 23-case benchmark,
`docs/BENCHMARK.md` for the object-scoped cut, and `docs/VALIDATION.md` for the
pre-registered extension. The parser is deliberately narrow: it reads the one
table it owns and fails if a row is renamed or removed.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
RESULTS_V1 = ROOT / "benchmark" / "results_v1.md"
RESULTS = ROOT / "benchmark" / "RESULTS.md"
BENCHMARK_MD = ROOT / "docs" / "BENCHMARK.md"
VALIDATION = ROOT / "docs" / "VALIDATION.md"

_COUNTS = ("TP", "FP", "TN", "FN", "INC_vuln", "INC_safe")


def _parts(line: str) -> list[str]:
    return [part.strip() for part in line.strip().strip("|").split("|")]


def _plain(cell: str) -> str:
    return cell.replace("**", "").strip()


def _ints(cell: str) -> int:
    return int(_plain(cell))


def _lead(cell: str) -> int:
    match = re.match(r"\d+", _plain(cell))
    assert match, f"expected a leading count in {cell!r}"
    return int(match.group())


def _ratio(cell: str) -> tuple[int, int]:
    match = re.fullmatch(r"(\d+) of (\d+)(?: safe)?", _plain(cell))
    assert match, f"expected 'N of M' in {cell!r}"
    return int(match.group(1)), int(match.group(2))


def _section(text: str, heading: str, *, level: int = 2) -> list[str]:
    lines = text.splitlines()
    start = lines.index(heading)
    prefix = "#" * level + " "
    for offset, line in enumerate(lines[start + 1:], start + 1):
        if line.startswith(prefix) and not line.startswith(prefix + "#"):
            return lines[start + 1:offset]
    return lines[start + 1:]


def _score_rows(path: Path) -> dict[tuple[str, str], dict[str, int]]:
    """Parse a generated benchmark Scores table into per-row counts."""
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| vampi |") and not line.startswith("| crapi |"):
            continue
        parts = _parts(line)
        if len(parts) != 13 or parts[2] != "ok":
            continue
        rows[(parts[0], parts[1])] = {
            key: int(parts[4 + index]) for index, key in enumerate(_COUNTS)
        }
    return rows


def _sum(rows, mode: str) -> dict[str, int]:
    totals = dict.fromkeys(_COUNTS, 0)
    for (_, row_mode), counts in rows.items():
        if row_mode != mode:
            continue
        for key in _COUNTS:
            totals[key] += counts[key]
    totals["Nv"] = totals["TP"] + totals["FN"] + totals["INC_vuln"]
    totals["Ns"] = totals["TN"] + totals["FP"] + totals["INC_safe"]
    return totals


def _at_a_glance() -> tuple[dict[str, tuple], dict[str, tuple]]:
    block = _section(README.read_text(encoding="utf-8"), "## At a glance")
    runs: dict[str, tuple] = {}
    objects: dict[str, tuple] = {}
    for line in block:
        if not line.startswith("| "):
            continue
        parts = _parts(line)
        if len(parts) == 5 and " of " in parts[1]:
            detected, false_positives = _ratio(parts[1]), _ratio(parts[2])
            value = (detected, false_positives, _ints(parts[3]), _lead(parts[4]))
            for key, prefix in (
                ("v1", "23-case benchmark"),
                ("strict", "Same 23 cases, strict"),
                ("lenient", "Same 23 cases, lenient"),
                ("extension_first", "Pre-registered extension"),
                ("extension_after", "Same extension"),
                ("post_headline", "Post-headline"),
            ):
                if parts[0].startswith(prefix):
                    runs[key] = value
        elif len(parts) == 2 and " of " in parts[1]:
            if parts[0].startswith("Strict"):
                objects["strict"] = _ratio(parts[1])
            elif parts[0].startswith("Lenient"):
                objects["lenient"] = _ratio(parts[1])
            elif parts[0].startswith("LedgerProbe"):
                objects["differential"] = _ratio(parts[1])
    return runs, objects


def _extension_row(anchor: str) -> dict[str, int]:
    lines = VALIDATION.read_text(encoding="utf-8").splitlines()
    start = lines.index(anchor)
    for line in lines[start + 1:]:
        if line.startswith("| **Overall** | **all** |"):
            parts = _parts(line)
            return {
                "Nv": _ints(parts[2]), "TP": _ints(parts[3]), "FN": _ints(parts[4]),
                "INC_vuln": _ints(parts[5]), "NR_v": _ints(parts[6]),
                "Ns": _ints(parts[8]), "TN": _ints(parts[9]), "FP": _ints(parts[10]),
                "INC_safe": _ints(parts[11]), "NR_s": _ints(parts[12]),
            }
    raise AssertionError(f"no extension Overall row after {anchor!r}")


def _post_headline_row() -> dict[str, int]:
    for line in VALIDATION.read_text(encoding="utf-8").splitlines():
        if line.startswith("| **Post-headline correction"):
            parts = _parts(line)
            # The corrected-total cell is TP/FP/TN/FN/INC_vuln/INC_safe/NOT RUN.
            tp, fp, tn, fn, inc_vuln, inc_safe, not_run = (
                int(value) for value in _plain(parts[1]).split("/")
            )
            return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
                    "INC_vuln": inc_vuln, "INC_safe": inc_safe,
                    # As in the extension tables, a vulnerable case is either
                    # detected, false-negative, abstained on, or not run.
                    "Nv": tp + fn + inc_vuln + not_run, "Ns": tn + fp + inc_safe,
                    "NR": not_run}
    raise AssertionError("post-headline corrected-total row is missing")


def _object_cut(path: Path = BENCHMARK_MD) -> dict[str, tuple[int, int]]:
    block = _section(path.read_text(encoding="utf-8"), "## Object-scoped-only cut")
    totals = {"strict": [0, 0], "lenient": [0, 0], "differential": [0, 0]}
    aliases = {"legacy_strict": "strict", "legacy_lenient": "lenient",
               "differential (v3)": "differential"}
    for line in block:
        if not re.match(r"\| (VAmPI|vampi|crAPI|crapi)\b", line):
            continue
        parts = _parts(line)
        # docs/BENCHMARK.md omits the Status column that benchmark/RESULTS.md has.
        offset = 1 if len(parts) == 13 else 0
        if len(parts) not in (12, 13):
            continue
        mode = aliases.get(parts[1], parts[1])
        if mode not in totals:
            continue
        totals[mode][0] += int(parts[4 + offset])
        totals[mode][1] += int(parts[2 + offset])
    return {key: tuple(value) for key, value in totals.items()}


def test_readme_at_a_glance_matches_recorded_results():
    runs, objects = _at_a_glance()
    assert set(runs) == {"v1", "strict", "lenient", "extension_first",
                         "extension_after", "post_headline"}, sorted(runs)
    assert set(objects) == {"strict", "lenient", "differential"}, sorted(objects)

    v1_rows = _score_rows(RESULTS_V1)
    v1 = _sum(v1_rows, "differential")
    strict = _sum(v1_rows, "legacy_strict")
    lenient = _sum(v1_rows, "legacy_lenient")

    expected = {
        "v1": ((v1["TP"], v1["Nv"]), (v1["FP"], v1["Ns"]),
               v1["INC_vuln"] + v1["INC_safe"], 0),
        "strict": ((strict["TP"], strict["Nv"]), (strict["FP"], strict["Ns"]),
                   strict["INC_vuln"] + strict["INC_safe"], 0),
        "lenient": ((lenient["TP"], lenient["Nv"]), (lenient["FP"], lenient["Ns"]),
                    lenient["INC_vuln"] + lenient["INC_safe"], 0),
    }

    first = _extension_row("## Run 1 results")
    expected["extension_first"] = (
        (first["TP"], first["Nv"]), (first["FP"], first["Ns"]),
        first["INC_vuln"] + first["INC_safe"], first["NR_v"] + first["NR_s"],
    )
    after = _extension_row("### After Amendments 1-2 counts")
    expected["extension_after"] = (
        (after["TP"], after["Nv"]), (after["FP"], after["Ns"]),
        after["INC_vuln"] + after["INC_safe"], after["NR_v"] + after["NR_s"],
    )
    post = _post_headline_row()
    expected["post_headline"] = (
        (post["TP"], post["Nv"]), (post["FP"], post["Ns"]),
        post["INC_vuln"] + post["INC_safe"], post["NR"],
    )

    assert runs == expected
    cut = _object_cut()
    assert objects == cut
    # The generated results file and the doc must agree on the cut.
    assert _object_cut(RESULTS) == cut

    # Guard the v1 aggregate against the published overall row.
    assert (v1["TP"], v1["FP"], v1["TN"], v1["FN"], v1["INC_vuln"], v1["INC_safe"]) == (
        10, 0, 4, 0, 3, 6)
