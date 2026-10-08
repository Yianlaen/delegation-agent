"""Evaluator-only fixed-truth authorizer and decision-layer panels."""

import random

from .data import TEST_KEY
from .runtime import authentic, make_receipt, mode
from .scoring import decision_score


def authorizer(authorized, coin, effectiveness):
    # This is synthetic screening, not a measured human authorization mechanism.
    outcome = "reject" if not authorized and coin < effectiveness else "approve"
    return lambda option, interaction: make_receipt(option, interaction, outcome, TEST_KEY)


def verification_panel(cases, truth, predictions, config):
    rows = []
    for case in cases:
        if case["study"] != "verification":
            continue
        t = truth[case["id"]]
        for source in ("oracle", "model"):
            mu = t["oracle_mu"] if source == "oracle" else predictions.get(case["prediction_id"])
            for r in config["verification_r"]:
                for condition in ("direct", "always", "cost_rule"):
                    for repeat, coin in enumerate(t["screen_coins"]):
                        row = {"case": case["id"], "split": case["split"], "family": case["family"],
                               "source": source, "r": r, "condition": condition, "repeat": repeat,
                               "mu_hat": mu, "oracle_mu": t["oracle_mu"], "authorized": t["authorized"],
                               "regime": t["regime"]}
                        if mu is None and condition == "cost_rule":
                            row["status"] = "invalid_prediction"
                        else:
                            confirm = condition == "always" or (condition == "cost_rule" and mode(
                                mu, r, case["loss"], case["cost"]) == "confirm")
                            o = {"id": case["option"], "claim": case["claim"], "authorizer": case["policy"]["authorizer"]}
                            receipt = authorizer(t["authorized"], coin, r)(o, case["id"]) if confirm else None
                            screened = bool(receipt and authentic(receipt, TEST_KEY) and receipt["payload"]["outcome"] == "reject")
                            expected = (t["oracle_mu"] * case["benefit"] - int(confirm) * case["cost"] -
                                        (1 - t["oracle_mu"]) * (1 - int(confirm) * r) * case["loss"])
                            row.update(status="complete", confirmed=confirm, blocked=screened,
                                       expected_utility=expected, receipt=receipt,
                                       **decision_score(t["authorized"], confirm, screened, case["loss"],
                                                        case["benefit"], case["cost"]))
                        rows.append(row)
    return rows


def screening_audit(case, settings, seed=20260915):
    rng = random.Random(seed)
    trials = [(j < 200, rng.random()) for j in range(1000)]
    option = {"id": case["option"], "claim": case["claim"], "authorizer": case["policy"]["authorizer"]}
    return [{"r": r, "trial": j, "authorized": authorized, "coin": coin,
             "receipt": authorizer(authorized, coin, r)(option, "screening-audit-" + str(j))}
            for r in settings for j, (authorized, coin) in enumerate(trials)]
