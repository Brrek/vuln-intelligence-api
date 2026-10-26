"""Transparent demonstration model; not a validated enterprise risk standard."""

from datetime import date

from .models import Intel, Observation, Risk, Weights


def prioritize(observation: Observation, intel: Intel, as_of: date, weights: Weights) -> Risk:
    if observation.last_seen > as_of:
        raise ValueError("observation is newer than assessment date")
    age = max(0, (as_of - observation.first_seen).days)
    factors = {
        "cvss": (observation.cvss or 0) / 10,
        "kev": float(intel.kev is True),
        "epss": intel.epss or 0,
        "criticality": observation.asset.criticality / 5,
        "environment": {"production": 1, "staging": 0.5, "development": 0.2, "unknown": 0.5}[
            observation.asset.environment
        ],
        "age": min(age / 90, 1),
    }
    contribution = {key: round(value * getattr(weights, key), 4) for key, value in factors.items()}
    explanation = [f"{key}: {value:.4f} points" for key, value in contribution.items()]
    explanation += [
        f"Finding age: {age} days; age contribution saturates at 90 days.",
        f"Asset context: criticality {observation.asset.criticality}/5; "
        f"{observation.asset.environment}; source {observation.asset.context_source}.",
    ]
    if observation.cvss is None:
        explanation.append("CVSS unavailable: zero contribution, not evidence of low severity.")
    if intel.kev is None or intel.epss is None:
        explanation.append(
            "Incomplete intelligence: unknown factors contribute zero; review manually."
        )
    return Risk(
        score=round(min(sum(contribution.values()), 100), 2),
        assessed_on=as_of,
        contributions=contribution,
        explanation=explanation,
        weights=weights.model_dump(),
    )
