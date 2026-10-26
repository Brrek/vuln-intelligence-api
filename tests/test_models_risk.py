from datetime import date

import pytest
from pydantic import ValidationError

from vuln_intelligence.config import Settings
from vuln_intelligence.enrichment import SyntheticIntel
from vuln_intelligence.models import Context, Observation, Severity, Weights, severity_for
from vuln_intelligence.providers import SyntheticScanner, normalize_tenable, scanner_date
from vuln_intelligence.risk import prioritize

from .conftest import AS_OF


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "unknown"),
        (0, "info"),
        (0.1, "low"),
        (3.9, "low"),
        (4, "medium"),
        (6.9, "medium"),
        (7, "high"),
        (8.9, "high"),
        (9, "critical"),
        (10, "critical"),
    ],
)
def test_severity_boundaries(value, expected):
    assert severity_for(value) == Severity(expected)


def test_identity_ignores_mutable_values_but_distinguishes_endpoint(raw):
    original = Observation.model_validate(raw)
    raw["cvss"] = 7
    raw["asset"]["hostname"] = "renamed.example.test"
    assert Observation.model_validate(raw).id == original.id
    raw["port"] = 8443
    assert Observation.model_validate(raw).id != original.id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cvss", 11),
        ("cvss", -1),
        ("cvss", float("nan")),
        ("port", 65536),
        ("first_seen", "2026-02-01"),
        ("protocol", "icmp"),
        ("source", "x/../../y"),
    ],
)
def test_invalid_observations(raw, field, value):
    raw[field] = value
    with pytest.raises(ValidationError):
        Observation.model_validate(raw)


def test_risk_exact_contributions_and_explanation(raw):
    observation = Observation.model_validate(raw)
    intel = SyntheticIntel().lookup(observation.vulnerability.cve, AS_OF)
    risk = prioritize(observation, intel, AS_OF, Weights())
    assert risk.score == 99.55
    assert risk.contributions == {
        "cvss": 30,
        "kev": 25,
        "epss": 14.55,
        "criticality": 15,
        "environment": 10,
        "age": 5,
    }
    assert len(risk.explanation) == 8
    assert risk.weights["kev"] == 25


def test_unknown_factors_are_explained(raw):
    raw["cvss"] = None
    observation = Observation.model_validate(raw)
    intel = SyntheticIntel().lookup(None, AS_OF)
    risk = prioritize(observation, intel, AS_OF, Weights())
    assert risk.score == 30
    assert any("CVSS unavailable" in text for text in risk.explanation)
    assert any("Incomplete intelligence" in text for text in risk.explanation)


def test_custom_weights_and_monotonicity(raw):
    observation = Observation.model_validate(raw)
    intel = SyntheticIntel().lookup(observation.vulnerability.cve, AS_OF)
    weights = Weights(cvss=100, kev=0, epss=0, criticality=0, environment=0, age=0)
    assert prioritize(observation, intel, AS_OF, weights).score == 100
    raw["cvss"] = 5
    assert prioritize(Observation.model_validate(raw), intel, AS_OF, weights).score == 50
    with pytest.raises(ValidationError):
        Weights(kev=26)
    with pytest.raises(ValueError):
        prioritize(observation, intel, date(2025, 1, 1), weights)


def test_tenable_normalization_context_and_multi_cve(tenable_raw):
    tenable_raw["plugin"]["cve"] += ["CVE-2022-0778", "CVE-2021-44228"]
    records = normalize_tenable(
        tenable_raw, {"asset-123": Context(criticality=5, environment="production")}
    )
    assert len(records) == 2
    record = Observation.model_validate(records[0])
    assert record.asset.context_source == "inventory"
    assert record.asset.criticality == 5
    assert record.protocol == "tcp"
    assert record.cvss == 9.8


def test_tenable_missing_optional_fields_and_unscored(tenable_raw):
    tenable_raw["plugin"] = {"id": 200, "name": "No CVE"}
    tenable_raw["asset"].pop("hostname")
    tenable_raw.pop("port")
    result = Observation.model_validate(normalize_tenable(tenable_raw, {})[0])
    assert result.vulnerability.id == "tenable-plugin-200"
    assert result.asset.environment == "unknown"
    assert result.asset.hostname == "asset-123"
    assert result.cvss is None
    assert result.port == 0
    tenable_raw["plugin"]["cvss_base_score"] = 4.0
    assert normalize_tenable(tenable_raw, {})[0]["cvss"] == 4
    tenable_raw["plugin"]["cve"] = "CVE-2021-44228"
    with pytest.raises(ValueError):
        normalize_tenable(tenable_raw, {})


def test_timestamp_and_synthetic_pagination():
    assert scanner_date(1767225600) == date(2026, 1, 1)
    assert list(SyntheticScanner(1).records()) == list(SyntheticScanner(3).records())
    with pytest.raises(ValueError):
        SyntheticScanner(0)


def test_environment_settings_and_secret_repr(monkeypatch):
    monkeypatch.setenv("TENABLE_ACCESS_KEY", "fake-test-access")
    monkeypatch.setenv("TENABLE_SECRET_KEY", "fake-test-secret")
    settings = Settings.from_env()
    assert "fake-test" not in repr(settings)
    with pytest.raises(ValueError):
        settings.require_live()
    monkeypatch.setenv("VULN_ENABLE_LIVE", "true")
    Settings.from_env().require_live()
