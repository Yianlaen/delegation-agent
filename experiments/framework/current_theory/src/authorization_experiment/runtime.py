"""Sequential reference runtime. Synthetic HMAC trust, not production identity."""

from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
import hmac
import json
import math


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


class Blocked(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def vector(value):
    return isinstance(value, list) and len(value) == 2 and all(number(x) for x in value)


def leq(left, right):
    return vector(left) and vector(right) and all(x <= y for x, y in zip(left, right))


def records(value):
    return {canonical(x) for x in value}


def mode(mu, r, loss, cost):
    require(all(number(x) for x in (mu, r, loss, cost)) and mu <= 1 and r <= 1,
            "invalid_cost_inputs")
    gain = Decimal(str(r)) * (1 - Decimal(str(mu))) * Decimal(str(loss)) - Decimal(str(cost))
    return "confirm" if gain >= 0 else "direct"


def sign(payload, key):
    return {"payload": deepcopy(payload), "signature": hmac.new(
        key, canonical(payload).encode(), sha256).hexdigest()}


def authentic(record, key):
    if not isinstance(record, dict) or set(record) != {"payload", "signature"}:
        return False
    try:
        return isinstance(record["signature"], str) and hmac.compare_digest(
            sign(record["payload"], key)["signature"], record["signature"])
    except (ValueError, TypeError):
        return False


def validate_claim(claim, policy):
    require(isinstance(claim, dict) and set(claim) == {"i", "P", "a", "R", "H", "E", "K"},
            "claim_schema")
    require(all(isinstance(claim[k], str) and claim[k] for k in ("i", "P", "a")), "claim_identity")
    require(claim["a"] == policy["action"], "action_unresolved")
    require(all(isinstance(claim[k], list) and all(isinstance(x, str) for x in claim[k])
                for k in ("R", "H")), "scope_schema")
    require(isinstance(claim["E"], list) and all(isinstance(x, list) and len(x) == 3 and
                all(isinstance(y, str) for y in x) for x in claim["E"]), "disclosure_schema")
    require(vector(claim["K"]), "cap_schema")
    require(set(claim["R"]) <= set(policy["R"]) and set(claim["H"]) <= set(policy["H"])
            and records(claim["E"]) <= records(policy["E"]), "admission_scope")
    require(policy["authorizer"] in policy["sufficient_authorizers"], "no_sufficient_authorizer")


def evidence_ok(proof, claim, authorizer, requester, option, policy, key, now):
    if not authentic(proof, key):
        return False
    p = proof["payload"]
    return (isinstance(p, dict) and p.get("kind") == "grant" and
            p.get("issuer") == authorizer and p.get("subject") == requester and
            p.get("option") == option and p.get("claim") == digest(claim) and
            p.get("policy") == policy["version"] and number(p.get("expires")) and
            now <= p["expires"] and p.get("channel") in {"sealed", "session"})


def make_grant(claim, policy, option, key, channel="session"):
    return sign({"kind": "grant", "issuer": policy["authorizer"],
                 "subject": policy["requester"], "option": option,
                 "claim": digest(claim), "policy": policy["version"],
                 "expires": 100, "channel": channel}, key)


def make_receipt(option, interaction, outcome, key):
    return sign({"kind": "confirmation", "interaction": interaction, "option": option["id"],
                 "claim": digest(option["claim"]), "issuer": option["authorizer"],
                 "outcome": outcome, "expires": 100}, key)


def reduced_claim(parent, child, substitutions, disclosure_substitutions=()):
    return (child["i"] == parent["i"] and child["P"] == parent["P"] and
            (parent["a"], child["a"]) in substitutions and
            set(child["R"]) <= set(parent["R"]) and set(child["H"]) <= set(parent["H"]) and
            all(e in parent["E"] or any((canonical(old), canonical(e)) in disclosure_substitutions
                                       for old in parent["E"]) for e in child["E"]) and
            leq(child["K"], parent["K"]))


class Runtime:
    """One interaction; caller owns the serialized deployment budget list."""

    def __init__(self, interaction, requester, options, policy, key, budget, expires=50):
        require(len(options) <= policy["n_max"] and len({o["id"] for o in options}) == len(options),
                "menu_bound")
        require(vector(budget), "budget_schema")
        self.interaction, self.requester = interaction, requester
        self.options = deepcopy({o["id"]: o for o in options})
        self.policy, self.key, self.budget = deepcopy(policy), key, budget
        self.expires, self.now = expires, 0
        self.untried, self.selected = set(self.options), None
        self.used, self.closed, self.finished = False, False, False
        self.phase, self.receipt, self.preaccepted = "select", None, False
        self.charges, self.disclosures, self.effects = [0, 0], set(), []
        self.trace, self.calls = [], 0

    def event(self, event, **fields):
        self.trace.append({"event": event, "option": self.selected, "time": self.now, **fields})

    def tick(self, now):
        require(number(now) and now >= self.now, "clock_reversal")
        self.now = now
        if now > self.expires:
            self.finish("expiry")
            raise Blocked("expiry")

    def eligible(self):
        if self.closed or self.finished:
            return []
        return sorted(o for o in self.untried if not self.used or self.options[o]["mode"] == "direct")

    def block(self, reason):
        self.event("block", reason=reason, allowance_used=self.used)
        self.phase = "select"
        if not self.eligible():
            self.finish("no_eligible_option")

    def select(self, option, requester, interaction):
        require(self.phase == "select" and option in self.eligible(), "selection_ineligible")
        require(requester == self.requester and interaction == self.interaction, "selection_binding")
        self.untried.remove(option)
        self.selected, self.receipt, self.preaccepted = option, None, False
        self.phase = "selected"
        self.event("select", mode=self.options[option]["mode"])

    def admission(self):
        o = self.options[self.selected]
        c, p = o["claim"], self.policy
        validate_claim(c, p)
        require(c["i"] == p["session"] and self.requester == p["requester"], "requester_context")
        require(o["authorizer"] == p["authorizer"] and p["admit"], "admission")
        require(leq(c["K"], self.budget), "cap_fit")
        require(o["mode"] in {"direct", "confirm"}, "mode_schema")
        require(not p["mandatory_confirmation"] or o["mode"] == "confirm", "mandatory_confirmation")

    def prepare(self):
        require(self.phase == "selected", "phase")
        try:
            self.tick(self.now)
            self.admission()
            self.event("admission", passed=True)
            o = self.options[self.selected]
            self.preaccepted = evidence_ok(o["proof"], o["claim"], o["authorizer"],
                                          self.requester, o["id"], self.policy, self.key, self.now)
            self.event("evidence", accepted=self.preaccepted)
            # This panel's policy requires a valid grant even after confirmation.
            require(self.preaccepted or (o["proof"] is None and self.policy["receipt_can_supply_grant"]), "mandatory_evidence")
            require(self.preaccepted or o["mode"] == "confirm", "insufficient_direct_proof")
            self.phase = "admitted"
            return True
        except Blocked as exc:
            self.block(str(exc))
            return False

    def confirm(self, client, warnings=()):
        require(self.phase == "admitted", "phase")
        o = self.options[self.selected]
        require(o["mode"] == "confirm", "not_confirm_mode")
        try:
            self.tick(self.now)
            self.admission()
            require(isinstance(warnings, (list, tuple)) and all(isinstance(x, str) for x in warnings), "warning_schema")
            facts = set(warnings)
            require(len(facts) <= self.policy["w_max"], "warning_bound")
            require(facts <= set(self.policy["warning_registry"]), "unknown_warning")
            checks = sorted({check for fact in facts for check in self.policy["warning_registry"][fact]})
            self.event("warning_checks", checks=checks)
            require(all(self.policy["checks"].get(c) is True for c in checks), "warning_check")
            require(not self.used, "allowance_consumed")
            require(self.policy["verification_available"], "verification_unavailable_pre_call")
            require(self.policy["confirmation_recipient"] == o["authorizer"] and
                    len(canonical(o).encode()) <= self.policy["confirmation_payload_bytes"], "confirmation_control_bound")
            self.used = True
            self.calls += 1
            self.event("authorizer_attempt", allowance_used=True)
            try:
                self.receipt = client(deepcopy(o), self.interaction)
            except (OSError, TimeoutError):
                self.receipt = None
            valid = authentic(self.receipt, self.key)
            payload = self.receipt["payload"] if valid else {}
            require(valid and len(canonical(self.receipt).encode()) <= self.policy["confirmation_receipt_bytes"] and
                    isinstance(payload, dict) and set(payload) == {"kind", "interaction", "option", "claim", "issuer", "outcome", "expires"} and
                    payload.get("kind") == "confirmation" and
                    payload.get("interaction") == self.interaction and payload.get("option") == o["id"] and
                    payload.get("claim") == digest(o["claim"]) and payload.get("issuer") == o["authorizer"] and
                    number(payload.get("expires")) and self.now <= payload["expires"], "invalid_receipt")
            self.event("confirmation", outcome=payload.get("outcome"))
            require(payload.get("outcome") == "approve", "confirmation_" + str(payload.get("outcome")))
            self.phase = "confirmed"
            return True
        except Blocked as exc:
            self.block(str(exc))
            return False

    def enter(self):
        require(self.phase in {"admitted", "confirmed"}, "phase")
        try:
            self.tick(self.now)
            self.admission()
            o = self.options[self.selected]
            require(o["id"] not in self.untried, "option_binding")
            require(o["mode"] == "direct" or self.phase == "confirmed", "confirmation_required")
            accepted = evidence_ok(o["proof"], o["claim"], o["authorizer"], self.requester,
                                   o["id"], self.policy, self.key, self.now)
            require(accepted or (o["proof"] is None and self.policy["receipt_can_supply_grant"] and self.phase == "confirmed"),
                    "final_evidence")
            self.closed, self.phase = True, "execution"
            self.event("enter_execution", proof_retained=o["proof"] is not None)
            return True
        except Blocked as exc:
            self.block(str(exc))
            return False

    def commit(self, effect):
        require(self.phase == "execution" and not self.finished, "execution_closed")
        self.tick(self.now)
        c = self.options[self.selected]["claim"]
        require(effect["a"] == c["a"] and set(effect["R"]) <= set(c["R"]), "effect_action_scope")
        require(set(effect["H"]) <= set(c["H"]), "effect_affected")
        disclosures = self.disclosures | records(effect["D"])
        require(disclosures <= records(c["E"]), "effect_disclosure")
        require(vector(effect["k"]), "effect_charge")
        total = [x + y for x, y in zip(self.charges, effect["k"])]
        require(leq(total, c["K"]) and leq(total, self.budget), "effect_cap")
        self.charges, self.disclosures = total, disclosures
        self.event("reserve", charge=effect["k"])
        self.effects.append(deepcopy(effect))
        self.event("commit", effect_hash=digest(effect))

    def finish(self, reason="complete"):
        if not self.finished:
            self.budget[:] = [x - y for x, y in zip(self.budget, self.charges)]
            self.finished, self.closed, self.phase = True, True, "finished"
            self.event("finish", reason=reason, charge=self.charges, remaining=self.budget[:])


def adapter(arguments, world):
    """Derive actual effects from requested arguments and trusted sandbox metadata."""
    require(isinstance(arguments, dict) and set(arguments) == {"action", "item", "recipient", "transform", "units"},
            "argument_schema")
    require(all(isinstance(arguments[x], str) for x in ("action", "item", "recipient", "transform")),
            "argument_types")
    require(type(arguments["units"]) is int and 1 <= arguments["units"] <= 20, "argument_units")
    a, item, recipient, transform, units = (arguments[x] for x in ("action", "item", "recipient", "transform", "units"))
    require(a in world["actions"] and item in world["items"] and recipient in world["recipients"], "unknown_argument")
    require(transform in world["items"][item]["views"], "unknown_transform")
    content = world["items"][item]["views"][transform]
    return {"a": a, "R": [item, "destination:" + recipient],
            "H": [world["items"][item]["principal"], world["recipients"][recipient], world["resource_principal"]],
            "D": [[item, recipient, transform]], "k": [units, len(content.encode()) * units],
            "content": content, "arguments": deepcopy(arguments)}
