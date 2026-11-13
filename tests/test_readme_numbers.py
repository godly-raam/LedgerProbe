"""Keep README counts tied to recorded results, and keep the docs free of
release metadata.

Two guards live here:

* every number in the README `At a glance` block must be derivable from a
  committed results record (`benchmark/results_v1.md`, `benchmark/RESULTS.md`,
  `docs/BENCHMARK.md`, `docs/VALIDATION.md`), and a false-positive rate must use
  the safe-case population as its denominator, not the case count of a cut;
* `README.md` and `docs/ROADMAP.md` must not hard-code a version or talk about
  releases. There are no formal releases, so those phrases only go stale.
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
ROADMAP = ROOT / "docs" / "ROADMAP.md"

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
    match = re.fullmatch(r"(\d+) of (\d+)(?: safe(?: cases)?)?", _plain(cell))
    assert match, f"expected 'N of M' in {cell!r}"
    return int(match.group(1)), int(match.group(2))


def _safe_ratio(cell: str) -> tuple[int, int]:
    """A rate whose denominator must be the safe-case population."""
    match = re.fullmatch(r"(\d+) of (\d+) safe cases", _plain(cell))
    assert match, f"expected 'N of M safe cases' in {cell!r}"
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


def _at_a_glance() -> dict[str, object]:
    block = _section(README.read_text(encoding="utf-8"), "## At a glance")
    runs: dict[str, tuple] = {}
    objects: dict[str, tuple[int, int]] = {}
    cut = None
    for line in block:
        match = re.search(r"cut is (\d+) cases \((\d+) vulnerable, (\d+) safe\)", line)
        if match:
            cut = tuple(int(group) for group in match.groups())
        if not line.startswith("| "):
            continue
        parts = _parts(line)
        if len(parts) == 5 and " of " in parts[1]:
            value = (
                _ratio(parts[1]),          # detected of vulnerable cases
                _safe_ratio(parts[2]),     # false positives of safe cases
                _ints(parts[3]),
                _lead(parts[4]),
            )
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
            for key, prefix in (("strict", "Strict"), ("lenient", "Lenient"),
                                ("differential", "LedgerProbe")):
                if parts[0].startswith(prefix):
                    objects[key] = _safe_ratio(parts[1])
    text = " ".join(block)
    v1_cut = re.search(r"v1 was also (\d+) of (\d+) safe cases in that cut", text)
    return {"runs": runs, "objects": objects, "cut": cut,
            "v1_cut": tuple(int(group) for group in v1_cut.groups()) if v1_cut else None}


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


def _object_cut(path: Path = BENCHMARK_MD) -> dict[str, dict[str, int]]:
    """Return FP, safe, vulnerable and total counts for every mode of the cut."""
    block = _section(path.read_text(encoding="utf-8"), "## Object-scoped-only cut")
    totals = {mode: dict.fromkeys(_COUNTS, 0)
              for mode in ("strict", "lenient", "differential")}
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
        # Counts start after Target/Mode/N (and Status, when present).
        for index, key in enumerate(_COUNTS):
            totals[mode][key] += int(parts[3 + offset + index])
    summary = {}
    for mode, counts in totals.items():
        safe = counts["TN"] + counts["FP"] + counts["INC_safe"]
        vulnerable = counts["TP"] + counts["FN"] + counts["INC_vuln"]
        summary[mode] = {"fp": counts["FP"], "safe": safe,
                         "vulnerable": vulnerable, "cases": safe + vulnerable}
    return summary


def _v1_object_cut() -> dict[str, int]:
    block = _section(BENCHMARK_MD.read_text(encoding="utf-8"),
                     "## Object-scoped-only cut")
    for line in block:
        if line.startswith("| v1 object-only |"):
            parts = _parts(line)  # Cut, N, TP, FP, TN, FN, INC_vuln, INC_safe
            fp, tn, inc_safe = int(parts[3]), int(parts[4]), int(parts[7])
            return {"fp": fp, "safe": tn + fp + inc_safe}
    raise AssertionError("v1 object-only aggregate row is missing")


def test_readme_at_a_glance_matches_recorded_results():
    glance = _at_a_glance()
    runs = glance["runs"]
    assert set(runs) == {"v1", "strict", "lenient", "extension_first",
                         "extension_after", "post_headline"}, sorted(runs)

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

    # Guard the v1 aggregate against the published overall row.
    assert (v1["TP"], v1["FP"], v1["TN"], v1["FN"], v1["INC_vuln"], v1["INC_safe"]) == (
        10, 0, 4, 0, 3, 6)


def test_readme_object_cut_uses_the_safe_case_denominator():
    glance = _at_a_glance()
    cut = _object_cut()
    # The generated results file and the doc must agree on the cut.
    assert _object_cut(RESULTS) == cut

    # "N of M safe cases", with M the safe population, never the cut size.
    assert glance["objects"] == {
        mode: (counts["fp"], counts["safe"]) for mode, counts in cut.items()
    }
    assert glance["objects"]["strict"] == (3, 3)
    assert glance["objects"]["lenient"] == (1, 3)
    assert glance["objects"]["differential"] == (0, 3)

    # The prose composition must match the recorded cut (same for every mode).
    assert {(counts["cases"], counts["vulnerable"], counts["safe"])
            for counts in cut.values()} == {(11, 8, 3)}
    assert glance["cut"] == (11, 8, 3)

    v1_cut = _v1_object_cut()
    assert glance["v1_cut"] == (v1_cut["fp"], v1_cut["safe"])
    assert glance["v1_cut"] == (0, 3)


_FENCE = re.compile(r"^\s*(```|~~~)")
_SEMVER = re.compile(r"(?<![\d.])\d+\.\d+\.\d+(?![\d.])")
_RELEASE = re.compile(r"\breleas(e|es|ed|ing)\b", re.IGNORECASE)


def _outside_code_fences(text: str) -> list[str]:
    kept, inside = [], False
    for line in text.splitlines():
        if _FENCE.match(line):
            inside = not inside
            continue
        if not inside:
            kept.append(line)
    return kept


def test_docs_have_no_hard_coded_version_or_release_wording():
    for path in (README, ROADMAP):
        prose = _outside_code_fences(path.read_text(encoding="utf-8"))
        versions = [line for line in prose if _SEMVER.search(line)]
        assert not versions, f"{path.name} hard-codes a version: {versions}"
        releases = [line for line in prose if _RELEASE.search(line)]
        assert not releases, f"{path.name} mentions a release: {releases}"
