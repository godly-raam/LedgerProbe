from runner import CONTROLS, PROFILES, score_surface


def test_vulnerable_profile_scores_low_and_reports_findings():
    report = score_surface(dict(PROFILES["vulnerable"]), mode="simulate", profile="vulnerable")
    assert report["run"]["score"] <= 20
    assert report["run"]["resilience"] == "weak"
    keys = {finding["check_id"] for finding in report["findings"]}
    assert {"AUTH-STRONGBOX", "AUTH-ATTESTATION", "AUTH-SIM-BINDING"} <= keys


def test_hardened_profile_scores_100():
    report = score_surface(dict(PROFILES["hardened"]), mode="simulate", profile="hardened")
    assert report["run"]["score"] == 100
    assert report["run"]["grade"] == "A"
    assert report["findings"] == []


def test_unobserved_controls_are_excluded_not_assumed_passing():
    surface = {key: None for _, key, _, _, _ in CONTROLS}
    report = score_surface(surface, mode="device", profile=None)
    assert report["run"]["score"] == 0
    assert report["run"]["controls_observed"] == 0
    assert report["findings"] == []
