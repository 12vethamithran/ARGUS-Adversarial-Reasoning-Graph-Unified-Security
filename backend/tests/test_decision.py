from app.engine.decision import calibrate_finding
from app.models.finding import Finding


def test_confirmed_sqli_remains_exploitable():
    finding = Finding(
        layer=1,
        title="EXPLOITED: SQLi",
        severity="critical",
        exploitable=True,
        confidence=0.85,
        evidence={
            "family": "sqli",
            "verdict": "exploited",
            "signal": "MySQL SQL error",
        },
    )

    calibrated = calibrate_finding(finding)

    assert calibrated.exploitable
    assert calibrated.severity == "critical"
    assert calibrated.evidence["decision"]["strength"] == "strong"


def test_sqli_without_exploit_signal_is_downgraded():
    finding = Finding(
        layer=1,
        title="Possible SQLi",
        severity="critical",
        exploitable=True,
        confidence=0.85,
        evidence={"family": "sqli", "verdict": "suspicious"},
    )

    calibrated = calibrate_finding(finding)

    assert not calibrated.exploitable
    assert calibrated.severity == "high"
    assert calibrated.confidence < 0.60
    assert calibrated.evidence["decision"]["adjusted"]


def test_low_confidence_exploitable_is_downgraded():
    finding = Finding(
        layer=1,
        title="Possible IDOR",
        severity="high",
        exploitable=True,
        confidence=0.55,
        evidence={"family": "idor", "verdict": "suspicious"},
    )

    calibrated = calibrate_finding(finding)

    assert not calibrated.exploitable
    assert calibrated.severity == "medium"
    assert calibrated.evidence["decision"]["reason"] == "confidence below exploitable threshold"
