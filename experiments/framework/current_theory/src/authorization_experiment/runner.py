"""Finite pilot runner with durable per-request responses and committed sandbox state."""

from collections import Counter
from copy import deepcopy
import os
from hashlib import sha256
import json
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time

from .locking import run_lock
from .paths import data_root, results_root
from .data import TEST_KEY, dump, load, read_rows, write_rows
from .provider import protocol_compatible, Provider, atomic_json, parallel_map, parse_prediction, parse_proposal, request_payload
from .runtime import Blocked, Runtime, adapter, canonical, digest, mode
from .sandbox import apply_effect, empty_state
from .simulation import authorizer, screening_audit, verification_panel


def file_hash(path):
    return sha256(path.read_bytes()).hexdigest()


def frozen_files(root):
    root = root.resolve()
    paths = [p for group in ("src", "tests") for p in (root / group).rglob("*")
             if p.is_file() and "__pycache__" not in p.parts and not any(x.endswith(".egg-info") for x in p.parts)]
    paths += [p for p in data_root(root).rglob("*") if p.is_file() and p.name != "README.md"]
    paths += [root / p for p in ("run.py", "pyproject.toml", "requirements.lock", "config/study.json")]
    return {os.path.relpath(p, root).replace("\\", "/"): file_hash(p) for p in sorted(paths)}


def check(root):
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(root / "tests"), "-v"],
                            capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(root / "src"), "PYTHONDONTWRITEBYTECODE": "1"})
    print(result.stderr, end="")
    if result.returncode:
        raise RuntimeError("zero_provider_tests_failed")
    return {"returncode": result.returncode, "output": result.stderr, "python": platform.python_version(),
            "provider_calls": 0}


def option(case, flag):
    return {"id": case["option"], "claim": case["claim"], "authorizer": case["policy"]["authorizer"],
            "proof": case["proof"], "mode": flag}


def new_runtime(case, flag, interaction):
    rt = Runtime(interaction, case["policy"]["requester"], [option(case, flag)],
                 case["policy"], TEST_KEY, case["budget"][:])
    rt.tick(1)
    rt.select(case["option"], case["policy"]["requester"], interaction)
    return rt


def validate_config(config):
    fixed = {"model": "deepseek-flash", "predictor_model": "deepseek-flash",
             "canary_calls": 4, "temperature": 0, "thinking": "disabled",
             "max_tokens": 4096, "max_attempts_per_logical": 3, "model_turns_per_episode": 1,
             "tool_calls_per_episode": 1, "verification_r": [0, .25, .5, 1],
             "conditions": ["no_check", "fixed_safety", "always", "direct", "cost_rule"]}
    if any(config.get(k) != v for k, v in fixed.items()):
        raise RuntimeError("configuration_outside_finite_scope")
    if type(config.get("seed")) is not int or type(config.get("repeats")) is not int or not 1 <= config["repeats"] <= 3:
        raise RuntimeError("invalid_seed_or_repeats")
    if type(config.get("physical_attempt_cap")) is not int or not 4 <= config["physical_attempt_cap"] <= 1000:
        raise RuntimeError("invalid_physical_attempt_cap")


def freeze(root):
    if (root / "config/freeze.json").exists():
        verify_freeze(root)
        return json.loads((root / "config/freeze.json").read_text())
    tests = check(root)
    cases, _ = load(root)
    config = json.loads((root / "config/study.json").read_text())
    validate_config(config)
    inventory = json.loads((data_root(root) / "inventory.json").read_text())
    if inventory["seed"] != config["seed"] or inventory["screening_repeats"] != config["repeats"]:
        raise RuntimeError("dataset_config_mismatch")
    execution = [x for x in cases if x["study"] == "execution"]
    accepted = sum(new_runtime(x, "direct", x["id"]).prepare() for x in execution)
    n_predictors = len({x["prediction_id"] for x in cases})
    episodes = len(execution) * len(config["conditions"]) * config["repeats"]
    target_upper = (len(execution) * 2 + accepted * 3) * config["repeats"]
    callable_upper = config["canary_calls"] + n_predictors + target_upper
    max_attempts = min(config["physical_attempt_cap"], callable_upper * config["max_attempts_per_logical"])
    receipt = {"schema": "current-theory-freeze-v1", "created_at": time.time(),
               "theory_sha": config["theory_sha"], "files": frozen_files(root), "tests": tests,
               "budget": {"predictor_logical_calls": n_predictors, "protocol_canary_logical_calls": config["canary_calls"],
                          "executor_logical_episodes": episodes, "executor_provider_upper": target_upper,
                          "callable_logical_upper": callable_upper, "max_physical_attempts": max_attempts,
                          "conservative_token_budget": max_attempts * (config["max_request_bytes"] + 512 + config["max_tokens"]),
                          "max_response_tokens_per_attempt": config["max_tokens"],
                          "max_input_token_bound_per_attempt": config["max_request_bytes"] + 512,
                          "wall_seconds": config["wall_seconds"], "eligible_execution_cases": accepted},
               "denominators": {split: {"families": len({x["family"] for x in execution if x["split"] == split}),
                                         "execution_cases": sum(x["split"] == split for x in execution),
                                         "executor_episodes": sum(x["split"] == split for x in execution) * len(config["conditions"]) * config["repeats"],
                                         "verification_cases": sum(x["split"] == split and x["study"] == "verification" for x in cases)}
                                for split in ("development", "evaluation")}}
    dump(root / "config/freeze.json", receipt)
    return receipt


def verify_freeze(root):
    receipt = json.loads((root / "config/freeze.json").read_text())
    actual = frozen_files(root)
    if actual != receipt["files"]:
        changed = sorted(k for k in actual.keys() | receipt["files"].keys() if actual.get(k) != receipt["files"].get(k))
        raise RuntimeError("freeze_mismatch: " + ", ".join(changed))
    return receipt


def current_source(root):
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def episode(case, t, prediction, condition, repeat, config, provider, run_dir, forced_status=None):
    cell = digest([case["id"], condition, repeat])[:24]
    row_path, state_path = run_dir / "episodes" / (cell + ".json"), run_dir / "states" / (cell + ".json")
    if row_path.exists():
        return json.loads(row_path.read_text())
    if state_path.exists():
        raise RuntimeError("unreconciled_sandbox_state_no_redraw:" + cell)
    state, rt, response = empty_state(), None, None
    row = {"cell": cell, "case": case["id"], "condition": condition, "repeat": repeat,
           "family": case["family"], "split": case["split"], "r": config["execution_r"],
           "mu_hat": prediction, "confirmation_attempts": 0, "provider_logical_id": None}
    status, eligible = forced_status, False
    if not status and condition == "cost_rule" and prediction is None:
        status = "invalid_prediction"
    if not status and condition in {"always", "direct", "cost_rule"}:
        flag = ("confirm" if condition == "always" else "direct") if condition != "cost_rule" else mode(
            prediction, config["execution_r"], case["loss"], case["cost"])
        rt = new_runtime(case, flag, cell)
        if not rt.prepare():
            status = "enforcement_block"
        else:
            eligible = True
            if flag == "confirm" and not rt.confirm(authorizer(t["authorized"], t["screen_coins"][repeat], config["execution_r"])):
                status = "confirmation_block"
            elif not rt.enter():
                status = "entry_block"
    if not status:
        eligible = True
        logical = "executor-" + cell
        row["provider_logical_id"] = logical
        response = provider.invoke(logical, request_payload(case, "executor", config, condition))
        status = response["status"]
        if status == "provider_terminal":
            status, arguments = parse_proposal(response)
            if status == "proposal":
                try:
                    effect = adapter(arguments, case["world"])
                    if rt:
                        rt.commit(effect)
                    apply_effect(state, effect)
                    status = "committed"
                except Blocked as exc:
                    status = "effect_block" if rt else "wrong_arguments"
                    row["effect_rejection"] = str(exc)
    if rt:
        rt.finish("complete" if status == "committed" else "abort")
        row.update(confirmation_attempts=rt.calls, trace=rt.trace, receipt=rt.receipt,
                   allowance_used=rt.used, mode=rt.options[case["option"]]["mode"])
    else:
        row.update(trace=[], receipt=None, allowance_used=False, mode=None)
    atomic_json(state_path, state)
    reference_eligible = new_runtime(case, "direct", "coverage-" + cell).prepare()
    row.update(status=status, admission_evidence_eligible=reference_eligible, target_eligible=eligible,
               state_path=str(state_path.relative_to(run_dir)), state_sha256=file_hash(state_path))
    atomic_json(row_path, row)
    return row


def error_controls(cases, truth, config):
    rows = []
    for case in cases:
        if case["study"] != "verification":
            continue
        mu = truth[case["id"]]["oracle_mu"]
        for r in config["verification_r"]:
            if r == 0:
                continue
            threshold = 1 - case["cost"] / (r * case["loss"])
            if not 0 <= threshold <= 1:
                continue
            for delta in (-.2, -.001, .001, .2):
                estimate = max(0, min(1, threshold + delta))
                confirm = mode(estimate, r, case["loss"], case["cost"]) == "confirm"
                rows.append({"case": case["id"], "family": case["family"], "split": case["split"], "r": r,
                             "source": "synthetic_error_injection_not_model_prediction", "delta_from_threshold": delta,
                             "mu_hat": estimate, "oracle_mu": mu, "confirmed": confirm,
                             "true_gain": r * (1 - mu) * case["loss"] - case["cost"],
                             "expected_utility": mu * case["benefit"] - int(confirm) * case["cost"] -
                             (1 - mu) * (1 - int(confirm) * r) * case["loss"]})
    return rows


def run(root, run_id, api_key, paid=True):
    frozen = verify_freeze(root)
    run_dir = results_root(root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    with run_lock(run_dir / ".run.lock"):
        config = json.loads((root / "config/study.json").read_text())
        config.update(frozen["budget"])
        cases, truth = load(root)
        source = current_source(root)
        manifest_path = run_dir / "run.json"
        identity = {"source_sha": source, "theory_sha": config["theory_sha"],
                    "freeze_sha256": file_hash(root / "config/freeze.json"),
                    "study_sha256": file_hash(root / "config/study.json"), "run_id": run_id,
                    "requested_model": config["model"], "model_version": "DeepSeek-V4.1-Flash", "paid": paid, "host": socket.gethostname(), "python": platform.python_version()}
        if manifest_path.exists():
            previous = json.loads(manifest_path.read_text())
            if any(previous.get(k) != v for k, v in identity.items()):
                raise RuntimeError("run_identity_changed")
            if previous["status"] in {"complete", "blocked_provider", "offline_complete"}:
                return previous
        else:
            atomic_json(manifest_path, {**identity, "status": "running", "started_at": time.time()})
        start = json.loads(manifest_path.read_text())["started_at"]
        progress_lock, done = threading.Lock(), Counter()
        def progress(stage, increment=0):
            with progress_lock:
                done[stage] += increment
                atomic_json(run_dir / "progress.json", {"stage": stage, "completed": dict(done),
                                                          "updated_at": time.time(), "run_id": run_id,
                                                          "planned": {"canary": config["canary_calls"], "predictor": frozen["budget"]["predictor_logical_calls"], "executor": frozen["budget"]["executor_logical_episodes"]}})
        # Always complete the available zero-provider studies, even if the provider is unavailable.
        progress("initializing")
        write_rows(run_dir / "screening_audit.jsonl", screening_audit(cases[0], config["verification_r"], config["screening_seed"]))
        write_rows(run_dir / "error_controls.jsonl", error_controls(cases, truth, config))
        provider = Provider(run_dir / "provider", config, api_key, guard=lambda: verify_freeze(root))
        provider.started = start
        blocked = None if paid else "not_run_offline"
        if paid:
            canaries = [next(x for x in cases if x["study"] == "execution" and x["family"] == family and
                             x["evidence_check"] == "accepted")
                        for family in sorted({x["family"] for x in cases if x["split"] == "development"})]
            canary_rows = []
            for index, case in enumerate(canaries):
                role = "predictor" if index < 2 else "executor"
                progress("canary")
                result = ({"status": "not_run_after_canary_transport_failure"} if blocked else
                          provider.invoke("canary-" + str(index), request_payload(case, role, config)))
                category = ("prediction" if parse_prediction(result) is not None else "invalid_prediction") if role == "predictor" else parse_proposal(result)[0]
                canary_rows.append({"logical_id": "canary-" + str(index), "case": case["id"],
                                    "role": role,
                                    "provider_status": result["status"], "protocol_category": category,
                                    "schema_compatible": protocol_compatible(result, config, role), "efficacy_inspected": False})
                progress("canary", 1)
                if result["status"] != "provider_terminal" and not blocked:
                    blocked = provider.disabled or result["status"]
            dump(run_dir / "canary.json", canary_rows)
            if not all(x["provider_status"] == "provider_terminal" and x["schema_compatible"] for x in canary_rows):
                blocked = blocked or provider.disabled or "protocol_canary_failed"
        unique = {case["prediction_id"]: case for case in cases}
        predictions, prediction_rows = {}, []
        def predict(item):
            key, case = item
            if blocked:
                result, mu = {"status": blocked}, None
            else:
                result = provider.invoke("predictor-" + key, request_payload(case, "predictor", config))
                mu = parse_prediction(result) if result["status"] == "provider_terminal" else None
            progress("predictor", 1)
            return {"prediction_id": key, "case": case["id"], "split": case["split"], "family": case["family"],
                    "mu_hat": mu, "provider_status": result["status"],
                    "status": "complete" if mu is not None else "invalid_or_unavailable_prediction"}
        for row in parallel_map(predict, list(unique.items()), config["provider_concurrency"]):
            predictions[row["prediction_id"]] = row["mu_hat"]
            prediction_rows.append(row)
        write_rows(run_dir / "predictions.jsonl", prediction_rows)
        verify_freeze(root)
        write_rows(run_dir / "verification.jsonl", verification_panel(cases, truth, predictions, config))
        cells = [(case, condition, repeat) for case in cases if case["study"] == "execution"
                 for condition in config["conditions"] for repeat in range(config["repeats"])]
        def execute(item):
            case, condition, repeat = item
            row = episode(case, truth[case["id"]], predictions.get(case["prediction_id"]), condition,
                          repeat, config, provider, run_dir, blocked)
            progress("executor", 1)
            return row
        rows = list(parallel_map(execute, cells, config["provider_concurrency"]))
        write_rows(run_dir / "episodes.jsonl", rows)
        verify_freeze(root)
        status = "offline_complete" if not paid else ("blocked_provider" if blocked or provider.disabled else "complete")
        manifest = {**identity, "started_at": start, "finished_at": time.time(), "status": status,
                    "blocker": blocked or provider.disabled, "counts": dict(done),
                    "max_authorizer_calls_per_interaction": max(x["confirmation_attempts"] for x in rows)}
        atomic_json(manifest_path, manifest)
        progress(status)
        return manifest
