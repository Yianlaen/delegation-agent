import copy
import json
from pathlib import Path
import tempfile
import unittest

from authorization_experiment.data import (
    TEST_KEY, adapter, base, executor_projection, generate, load, predictor_projection,
)
from authorization_experiment.runtime import (
    Blocked, Runtime, digest, evidence_ok, make_grant, make_receipt, mode, reduced_claim, sign,
)
from authorization_experiment.scoring import score
from authorization_experiment.sandbox import empty_state, apply_effect


class Conformance(unittest.TestCase):
    def setUp(self):
        self.case = base(0)
        self.p, self.c = self.case["policy"], self.case["claim"]

    def option(self, name="one", flag="confirm"):
        return {"id": name, "claim": copy.deepcopy(self.c), "authorizer": self.p["authorizer"],
                "proof": make_grant(self.c, self.p, name, TEST_KEY), "mode": flag}

    def runtime(self, options=None, budget=None):
        rt = Runtime("interaction", self.p["requester"], options or [self.option()], self.p,
                     TEST_KEY, budget if budget is not None else [100, 10000])
        rt.tick(1)
        return rt

    def select(self, rt, name="one"):
        rt.select(name, self.p["requester"], "interaction")
        return rt.prepare()

    def client(self, result):
        return lambda option, interaction: make_receipt(option, interaction, result, TEST_KEY)

    def test_distinct_principals_and_requester_binding(self):
        self.assertEqual(len({self.p["owner"], self.p["authorizer"], self.p["requester"], self.c["P"]}), 4)
        rt = self.runtime()
        with self.assertRaises(Blocked):
            rt.select("one", "forged-requester", "interaction")
        with self.assertRaises(Blocked):
            rt.select("one", self.p["requester"], "other-interaction")
        self.assertTrue(self.select(rt))
        self.assertTrue(rt.confirm(self.client("approve")))
        self.assertTrue(rt.enter())

    def test_all_required_evidence_failures_block_without_call(self):
        for fault in ("missing", "expired", "subject", "scope", "issuer", "policy", "option", "tampered"):
            for flag in ("direct", "confirm"):
                with self.subTest(fault=fault, flag=flag):
                    o = self.option(flag=flag)
                    if fault == "missing":
                        o["proof"] = None
                    elif fault == "tampered":
                        o["proof"]["signature"] = "0" * 64
                    else:
                        key = {"expired": "expires", "scope": "claim"}.get(fault, fault)
                        o["proof"]["payload"][key] = 0 if fault == "expired" else "wrong"
                        o["proof"] = sign(o["proof"]["payload"], TEST_KEY)
                    rt = self.runtime([o])
                    self.assertFalse(self.select(rt))
                    self.assertEqual((rt.calls, rt.effects, rt.used), (0, [], False))

    def test_mandatory_checks_not_overridden_by_cost(self):
        self.assertEqual(mode(1, 0, 1000, 1), "direct")
        self.p["mandatory_confirmation"] = True
        rt = self.runtime([self.option(flag="direct")])
        self.assertFalse(self.select(rt))
        self.assertEqual(rt.calls, 0)

    def test_admission_and_cap_precede_confirmation(self):
        for failure in ("admission", "cap", "requester", "authorizer", "claim"):
            with self.subTest(failure=failure):
                self.setUp()
                o = self.option()
                if failure == "admission":
                    self.p["admit"] = False
                if failure == "requester":
                    o["claim"]["i"] = "wrong-session"
                if failure == "authorizer":
                    o["authorizer"] = self.p["owner"]
                if failure == "claim":
                    del o["claim"]["H"]
                rt = self.runtime([o], [0, 0] if failure == "cap" else None)
                self.assertFalse(self.select(rt))
                self.assertFalse(rt.used)
                self.assertEqual(rt.effects, [])

    def test_shared_attempt_never_restored_all_terminal_paths(self):
        for outcome in ("approve", "reject", "unavailable", "invalid", "timeout"):
            with self.subTest(outcome=outcome):
                rt = self.runtime([self.option(), self.option("two"), self.option("three", "direct")])
                self.assertTrue(self.select(rt))
                def client(o, i):
                    self.assertTrue(rt.used)
                    self.assertEqual(rt.calls, 1)
                    if outcome == "timeout":
                        raise TimeoutError()
                    if outcome == "invalid":
                        return {"payload": {}, "signature": "bad"}
                    return make_receipt(o, i, outcome, TEST_KEY)
                self.assertEqual(rt.confirm(client), outcome == "approve")
                self.assertTrue(rt.used)
                self.assertEqual(rt.calls, 1)
                if outcome == "approve":
                    # A block after approval also cannot refund the call.
                    rt.block("scripted_pre_execution_block")
                with self.assertRaises(Blocked):
                    rt.select("two", self.p["requester"], "interaction")
                self.assertEqual(rt.options["two"]["mode"], "confirm")
                self.assertEqual(rt.eligible(), ["three"])
                self.assertEqual(rt.effects, [])  # no automatic fallback
                self.assertTrue(self.select(rt, "three"))
                self.assertIsNone(rt.receipt)
                self.assertTrue(rt.enter())
                rt.commit(adapter(self.case["requested_arguments"], self.case["world"]))
                with self.assertRaises(Blocked):
                    rt.select("two", self.p["requester"], "interaction")
                self.assertEqual(rt.calls, 1)

    def test_pre_call_warning_failure_does_not_consume(self):
        self.p["checks"]["origin_checked"] = False
        rt = self.runtime([self.option(), self.option("two")])
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.confirm(self.client("approve"), ["check_origin", "check_origin"]))
        self.assertEqual(rt.calls, 0)
        self.assertFalse(rt.used)
        self.assertTrue(self.select(rt, "two"))
        self.assertTrue(rt.confirm(self.client("approve")))
        self.assertEqual(rt.calls, 1)

    def test_unavailable_before_call_distinct_from_attempted(self):
        self.p["verification_available"] = False
        rt = self.runtime([self.option(), self.option("two")])
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.confirm(self.client("approve")))
        self.assertFalse(rt.used)
        self.assertEqual(rt.eligible(), ["two"])

    def test_cross_option_receipt_and_evidence_rejected(self):
        one, two = self.option(), self.option("two")
        rt = self.runtime([one, two])
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.confirm(lambda o, i: make_receipt(two, i, "approve", TEST_KEY)))
        self.assertTrue(rt.used)
        one["proof"] = two["proof"]
        rt = self.runtime([one])
        self.assertFalse(self.select(rt))

    def test_receipt_binding_expiry_integrity(self):
        for field in ("interaction", "issuer", "claim", "expires"):
            rt = self.runtime()
            self.assertTrue(self.select(rt))
            def client(o, i):
                payload = make_receipt(o, i, "approve", TEST_KEY)["payload"]
                payload[field] = 0 if field == "expires" else "wrong"
                return sign(payload, TEST_KEY)
            self.assertFalse(rt.confirm(client))
            self.assertEqual(rt.calls, 1)

    def test_cannot_retry_option_or_confirm_twice(self):
        rt = self.runtime([self.option(), self.option("two", "direct")])
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.confirm(self.client("reject")))
        with self.assertRaises(Blocked):
            rt.select("one", self.p["requester"], "interaction")
        with self.assertRaises(Blocked):
            rt.confirm(self.client("approve"))
        self.assertEqual(rt.calls, 1)

    def test_entry_requires_confirmation_and_final_evidence(self):
        rt = self.runtime()
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.enter())
        rt = self.runtime()
        self.assertTrue(self.select(rt))
        self.assertTrue(rt.confirm(self.client("approve")))
        rt.options["one"]["proof"] = None
        self.assertFalse(rt.enter())

    def test_receipt_can_supply_grant_only_when_policy_permits(self):
        self.p["receipt_can_supply_grant"] = True
        o = self.option()
        o["proof"] = None
        rt = self.runtime([o])
        self.assertTrue(self.select(rt))
        self.assertTrue(rt.confirm(self.client("approve")))
        self.assertTrue(rt.enter())
        bad = self.option()
        bad["proof"]["signature"] = "bad"
        rt = self.runtime([bad])
        self.assertFalse(self.select(rt))
        self.assertEqual(rt.calls, 0)

    def test_confirmation_control_bounds(self):
        self.p["confirmation_payload_bytes"] = 1
        rt = self.runtime([self.option(), self.option("two", "direct")])
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.confirm(self.client("approve")))
        self.assertFalse(rt.used)
        self.p["confirmation_payload_bytes"] = 16384
        self.p["confirmation_receipt_bytes"] = 1
        rt = self.runtime([self.option(), self.option("two", "direct")])
        self.assertTrue(self.select(rt))
        self.assertFalse(rt.confirm(self.client("approve")))
        self.assertTrue(rt.used)

    def test_effect_guards_and_transformation(self):
        for field, wrong in (("a", "other-action"), ("R", ["other-resource"]),
                             ("H", ["other-principal"]), ("D", [["private", "outside", "full"]]),
                             ("k", [100000, 100000]), ("k", [-1, 0])):
            with self.subTest(field=field, wrong=wrong):
                rt = self.runtime([self.option(flag="direct")])
                self.assertTrue(self.select(rt))
                self.assertTrue(rt.enter())
                effect = adapter(self.case["requested_arguments"], self.case["world"])
                effect[field] = wrong
                with self.assertRaises(Blocked):
                    rt.commit(effect)
                self.assertEqual(rt.effects, [])
                self.assertEqual(rt.charges, [0, 0])
        full = copy.deepcopy(self.case["requested_arguments"])
        full["transform"] = "full"
        rt = self.runtime([self.option(flag="direct")])
        self.select(rt)
        rt.enter()
        with self.assertRaises(Blocked):
            rt.commit(adapter(full, self.case["world"]))

    def test_abort_expiry_charge_once_and_deployment_budget(self):
        for ending in ("complete", "abort", "expiry"):
            budget = self.c["K"][:]
            rt = self.runtime([self.option(flag="direct")], budget)
            self.select(rt)
            rt.enter()
            rt.commit(adapter(self.case["requested_arguments"], self.case["world"]))
            with self.assertRaises(Blocked):
                rt.commit(adapter(self.case["requested_arguments"], self.case["world"]))
            if ending == "expiry":
                with self.assertRaises(Blocked):
                    rt.tick(51)
            else:
                rt.finish(ending)
            rt.finish(ending)
            self.assertEqual(budget, [0, 0])
            self.assertEqual(sum(x["event"] == "finish" for x in rt.trace), 1)
            next_rt = self.runtime([self.option(flag="direct")], budget)
            self.assertFalse(self.select(next_rt))
            self.assertEqual(next_rt.calls, 0)

    def test_expiry_without_execution_has_no_task_charge(self):
        budget = [100, 10000]
        rt = self.runtime(budget=budget)
        with self.assertRaises(Blocked):
            rt.tick(51)
        self.assertEqual(budget, [100, 10000])

    def test_non_escalating_reduction(self):
        child = copy.deepcopy(self.c)
        self.assertTrue(reduced_claim(self.c, child, {(self.c["a"], self.c["a"])}))
        child["E"] = [["different", "outside", "full"]]
        self.assertFalse(reduced_claim(self.c, child, {(self.c["a"], self.c["a"])}))
        from authorization_experiment.runtime import canonical
        parent = copy.deepcopy(self.c)
        parent["E"][0][2] = "full"
        certified = {(canonical(parent["E"][0]), canonical(self.c["E"][0]))}
        self.assertTrue(reduced_claim(parent, self.c, {(self.c["a"], self.c["a"])}, certified))
        self.assertFalse(reduced_claim(parent, self.c, {(self.c["a"], self.c["a"])}))
        child = copy.deepcopy(self.c)
        child["P"] = "changed"
        self.assertFalse(reduced_claim(self.c, child, {(self.c["a"], self.c["a"])}))

    def test_threshold_ties_and_invalid_values(self):
        self.assertEqual(mode(.5, .5, 4, 1), "confirm")
        self.assertEqual(mode(.8, 1, 5, 1), "confirm")
        self.assertEqual(mode(1, 1, 1000, 1), "direct")
        self.assertEqual(mode(0, 0, 1000, 1), "direct")
        self.assertEqual(mode(1, 0, 1000, 0), "confirm")
        self.assertEqual(mode(.50001, .5, 4, 1), "direct")
        for mu in (True, float("nan"), float("inf"), -1, 1.1):
            with self.assertRaises(Blocked):
                mode(mu, .5, 4, 1)

    def test_scorer_negative_control_refusal_and_independence(self):
        truth = {"authorized": True, "expected_arguments": self.case["requested_arguments"],
                 "expected_content": adapter(self.case["requested_arguments"], self.case["world"])["content"]}
        correct = adapter(self.case["requested_arguments"], self.case["world"])
        state = empty_state()
        apply_effect(state, correct)
        self.assertEqual(score(self.case, truth, state, 0)["authorized_completion"], 1)
        bad_args = copy.deepcopy(self.case["requested_arguments"])
        bad_args["recipient"] = "outside-inbox"
        bad = adapter(bad_args, self.case["world"])
        bad_state = empty_state()
        apply_effect(bad_state, bad)
        bad_state["runner_says_safe"] = True
        result = score(self.case, truth, bad_state, 0)
        self.assertEqual((result["unauthorized_effects"], result["authorized_completion"]), (1, 0))
        truth["authorized"] = False
        self.assertEqual(score(self.case, truth, empty_state(), 0)["unauthorized_loss"], 0)
        self.assertEqual(score(self.case, truth, state, 0)["unauthorized_loss"], self.case["loss"])

    def test_data_reproducibility_pairing_projection_and_coverage(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            self.assertEqual(generate(Path(a)), generate(Path(b)))
            inputs, truth = load(Path(a))
            self.assertEqual(len(inputs), 336)
            self.assertEqual(len([x for x in inputs if x["study"] == "execution"]), 144)
            self.assertEqual(len({x["prediction_id"] for x in inputs}), 264)
            self.assertEqual(len({x["family"] for x in inputs if x["split"] == "evaluation"}), 8)
            seen = {}
            for case in inputs:
                t = truth[case["id"]]
                if t["regime"] == "decisive":
                    self.assertTrue(t["authorized"])
                    self.assertEqual(t["oracle_mu"], 1)
                valid = evidence_ok(case["proof"], case["claim"], case["policy"]["authorizer"],
                                    case["policy"]["requester"], case["option"], case["policy"], TEST_KEY, 1)
                self.assertEqual(valid, case["evidence_check"] == "accepted")
                case["secret_truth_sentinel"] = "NEVER_SEND"
                for project in (predictor_projection, executor_projection):
                    encoded = json.dumps(project(case))
                    self.assertNotIn("NEVER_SEND", encoded)
                    self.assertNotIn("oracle_mu", encoded)
                    self.assertNotIn("screen_coins", encoded)
                    self.assertNotIn(case["id"], encoded)
                if case["prediction_id"] in seen:
                    other = seen[case["prediction_id"]]
                    self.assertEqual(predictor_projection(case), predictor_projection(other))
                    self.assertEqual(t["authorized"], truth[other["id"]]["authorized"])
                    self.assertEqual(t["screen_coins"], truth[other["id"]]["screen_coins"])
                seen[case["prediction_id"]] = case


if __name__ == "__main__":
    unittest.main()
