"""ST-AI Framework — Secure Tropos Model
=================================================================

The canonical Secure Tropos artefacts derived from the registry state.
Each PCS sub-term traces back to a goal (what we want), an anti-goal
(what an attacker wants), and a security constraint (what mediates
them). The actor-dependency graph shows trust delegations between
trainer / validator / deployer / operator / consumer roles.

This module is the *one Tropos model* — pages render different views
(graph, tree, catalogue) of the same underlying object.

References:
    Mouratidis & Giorgini (2007), Secure Tropos: a security-oriented
        extension of the Tropos methodology.
    Giorgini, Massacci, Mylopoulos & Zannone (2005), Modelling security
        requirements through ownership, permission and delegation.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Tuple


# ── Actor roles in the AI deployment dependency chain ────────────────────────
class ActorRoleEnum(str, Enum):
    """The five canonical actor roles in an AI deployment.

    Order matters: each role depends on the role(s) immediately upstream.
    A consumer depends on the operator; the operator depends on the deployer;
    the deployer depends on the validator; the validator depends on the trainer.
    """
    TRAINER   = "TRAINER"        # builds the model
    VALIDATOR = "VALIDATOR"      # verifies fitness for purpose
    DEPLOYER  = "DEPLOYER"       # puts the model into production
    OPERATOR  = "OPERATOR"       # runs the deployed system day-to-day
    CONSUMER  = "CONSUMER"       # acts on model outputs


# ── Trust delegation types ───────────────────────────────────────────────────
class TrustTypeEnum(str, Enum):
    """The type of dependency between two actors.

    Secure Tropos distinguishes hard dependencies (the dependee MUST act)
    from soft dependencies (the dependee SHOULD act). For AI, we also need
    to mark fail-open dependencies (no enforcement, only good faith).
    """
    HARD = "HARD"           # contractual, auditable, enforceable
    SOFT = "SOFT"           # documented expectation, no enforcement
    FAIL_OPEN = "FAIL_OPEN" # no documented expectation


@dataclass
class Actor:
    """A role-bearer in the AI deployment dependency chain."""
    role:        ActorRoleEnum
    identifier:  str                            # email, staff ID, vendor name
    label:       str                            # human-readable display name
    is_internal: bool = True                    # in-org vs third-party
    consolidated_with: List[ActorRoleEnum] = field(default_factory=list)
    # If non-empty, this physical actor also plays these other roles
    # (RCF risk indicator — same human as trainer + validator, etc.).


@dataclass
class TrustDelegation:
    """A directed trust edge from one actor to another.

    Reads as 'depender trusts dependee for permission/scope'.
    Example: CONSUMER trusts DEPLOYER for "model output is fit for clinical use"
             under HARD type, scope "diagnostic recommendations only".
    """
    depender:   ActorRoleEnum
    dependee:   ActorRoleEnum
    permission: str                # what's being delegated
    scope:      str                # under what limits
    trust_type: TrustTypeEnum = TrustTypeEnum.SOFT
    expires:    Optional[str] = None         # ISO date or None
    evidence:   Optional[str] = None         # document URL / hash if AUDITED


# ── Goal-anti-goal-threat-constraint ────────────────────────────────────────
@dataclass
class Goal:
    """An intentional element the system is supposed to achieve.

    In Secure Tropos every PCS sub-term is anchored to at least one goal:
    'L is bounded' anchors to 'adversarial events are infrequent', etc.
    """
    goal_id:     str
    name:        str
    description: str
    pcs_term:    str                # which PCS variable the goal binds
    held_by:     ActorRoleEnum      # which actor commits to this goal


@dataclass
class AntiGoal:
    """What the adversary wants — the negation of a goal.

    AntiGoals are explicit so the threat model is auditable. For every
    goal there is at least one anti-goal an attacker would pursue to
    defeat it.
    """
    anti_goal_id: str
    name:         str
    description:  str
    threatens:    str               # goal_id this anti-goal contradicts
    attacker_role: str              # "external", "insider", "supply chain", ...


@dataclass
class Threat:
    """A concrete attack pattern that could realise an anti-goal."""
    threat_id:    str
    name:         str
    description:  str
    realises:     str               # anti_goal_id this threat instantiates
    cve_refs:     List[str] = field(default_factory=list)
    mitre_refs:   List[str] = field(default_factory=list)


@dataclass
class SecurityConstraint:
    """A named constraint imposed by one actor on a dependency.

    Reads as 'imposed_by REQUIRES that on_dependency, condition holds,
    because threat_id would otherwise materialise'.
    Example: imposed_by = AI Governance Board,
             on_dependency = TRAINER → VALIDATOR delegation,
             condition = 'distinct natural persons',
             because = THR-RCF-1 (single-actor consolidation).
    """
    constraint_id: str
    name:          str
    description:   str
    imposed_by:    str               # actor or governance body
    on_dependency: Tuple[ActorRoleEnum, ActorRoleEnum]
    condition:     str               # the rule that must hold
    because:       str               # threat_id mitigated
    pcs_term:      str               # PCS variable this constraint binds
    standard_refs: List[str] = field(default_factory=list)
    # Cross-references to NIST / ISO / EU AI Act clauses
    is_satisfied:  bool = False      # whether the registry currently satisfies it
    why_unsatisfied: str = ""


# ── The full Tropos model ────────────────────────────────────────────────────
@dataclass
class TroposModel:
    """The whole Secure Tropos model for a deployment.

    Built by derive_tropos_model(registry, derived_terms).
    Pages render different views of this single object.
    """
    actors:       List[Actor]              = field(default_factory=list)
    delegations:  List[TrustDelegation]    = field(default_factory=list)
    goals:        List[Goal]               = field(default_factory=list)
    anti_goals:   List[AntiGoal]           = field(default_factory=list)
    threats:      List[Threat]             = field(default_factory=list)
    constraints:  List[SecurityConstraint] = field(default_factory=list)

    def goals_for_pcs_term(self, term: str) -> List[Goal]:
        return [g for g in self.goals if g.pcs_term == term]

    def constraints_for_pcs_term(self, term: str) -> List[SecurityConstraint]:
        return [c for c in self.constraints if c.pcs_term == term]

    def violated_constraints(self) -> List[SecurityConstraint]:
        return [c for c in self.constraints if not c.is_satisfied]

    def actor_by_role(self, role: ActorRoleEnum) -> Optional[Actor]:
        for a in self.actors:
            if a.role == role:
                return a
        return None


def derive_tropos_model(reg, derived_terms) -> TroposModel:
    """Build the Tropos model from the current registry + derived state.

    This is the equivalent of derive_terms() but for the Tropos artefacts.
    Pulling from both reg and derived_terms means the Tropos model reflects
    the same gate-decision logic as the PCS — they're not two independent
    universes.
    """
    from framework.tropos_catalogue import (
        CANONICAL_GOALS, CANONICAL_ANTI_GOALS,
        CANONICAL_THREATS, CANONICAL_CONSTRAINTS,
    )

    model = TroposModel()

    # ── Actors — derive from registry identifiers ──────────────────────
    # Defensive: read identifiers if present, otherwise leave the label blank.
    def _ident(field_name: str, default: str = "(undeclared)") -> str:
        return getattr(reg, field_name, None) or default

    trainer_id   = _ident("trainer_id")
    validator_id = _ident("validator_id")
    deployer_id  = _ident("deployer_id")
    operator_id  = _ident("operator_id", "(operator role)")
    consumer_id  = _ident("consumer_id", "(consumer role)")

    # Detect actor consolidation (the RCF signal at the Tropos level)
    same_t_v = bool(getattr(reg, "trainer_is_validator", False))
    same_v_d = bool(getattr(reg, "validator_is_deployer", False))
    same_t_d = bool(getattr(reg, "trainer_is_deployer", False))

    model.actors.append(Actor(
        role=ActorRoleEnum.TRAINER,
        identifier=trainer_id,
        label=f"Trainer · {trainer_id}",
        is_internal=True,
        consolidated_with=(
            ([ActorRoleEnum.VALIDATOR] if same_t_v else []) +
            ([ActorRoleEnum.DEPLOYER]  if same_t_d else [])
        ),
    ))
    model.actors.append(Actor(
        role=ActorRoleEnum.VALIDATOR,
        identifier=validator_id,
        label=f"Validator · {validator_id}",
        is_internal=True,
        consolidated_with=(
            ([ActorRoleEnum.TRAINER]  if same_t_v else []) +
            ([ActorRoleEnum.DEPLOYER] if same_v_d else [])
        ),
    ))
    model.actors.append(Actor(
        role=ActorRoleEnum.DEPLOYER,
        identifier=deployer_id,
        label=f"Deployer · {deployer_id}",
        is_internal=True,
        consolidated_with=(
            ([ActorRoleEnum.TRAINER]   if same_t_d else []) +
            ([ActorRoleEnum.VALIDATOR] if same_v_d else [])
        ),
    ))
    model.actors.append(Actor(
        role=ActorRoleEnum.OPERATOR,
        identifier=operator_id,
        label=f"Operator · {operator_id}",
        is_internal=True,
    ))
    model.actors.append(Actor(
        role=ActorRoleEnum.CONSUMER,
        identifier=consumer_id,
        label=f"Consumer · {consumer_id}",
        is_internal=True,
    ))

    # ── Trust delegations — the dependency chain ──────────────────────
    # Each edge is annotated with the trust type derived from the registry's
    # governance maturity, evidence, and assessment-mode declarations.
    from framework.assessment_mode import AssessmentModeEnum
    mode = getattr(reg, "assessment_mode", AssessmentModeEnum.SELF)
    if mode == AssessmentModeEnum.AUDITED:
        default_trust = TrustTypeEnum.HARD
    elif mode == AssessmentModeEnum.VALIDATED:
        default_trust = TrustTypeEnum.SOFT
    else:
        default_trust = TrustTypeEnum.FAIL_OPEN

    # Trainer → Validator: model fitness
    model.delegations.append(TrustDelegation(
        depender=ActorRoleEnum.VALIDATOR,
        dependee=ActorRoleEnum.TRAINER,
        permission="train a model fit for the declared domain",
        scope=f"model type = {getattr(reg.model_type, 'value', '?')}",
        trust_type=default_trust if not same_t_v else TrustTypeEnum.FAIL_OPEN,
        evidence="model card approved" if getattr(reg, "model_card_approved", False) else None,
    ))
    # Validator → Deployer: validation evidence
    model.delegations.append(TrustDelegation(
        depender=ActorRoleEnum.DEPLOYER,
        dependee=ActorRoleEnum.VALIDATOR,
        permission="certify model meets deployment criteria",
        scope=f"audit cadence = {getattr(reg.audit_frequency, 'value', '?')}",
        trust_type=default_trust if not same_v_d else TrustTypeEnum.FAIL_OPEN,
    ))
    # Deployer → Operator: operational handover
    model.delegations.append(TrustDelegation(
        depender=ActorRoleEnum.OPERATOR,
        dependee=ActorRoleEnum.DEPLOYER,
        permission="release model to production",
        scope="under documented HITL constraints",
        trust_type=default_trust,
        evidence="HITL formally specified"
            if getattr(reg, "hitl_formally_specified", False) else None,
    ))
    # Operator → Consumer: trustworthy outputs
    model.delegations.append(TrustDelegation(
        depender=ActorRoleEnum.CONSUMER,
        dependee=ActorRoleEnum.OPERATOR,
        permission="present model outputs as decision support",
        scope=f"AI criticality = {getattr(reg.ai_criticality, 'value', '?')}",
        trust_type=default_trust,
        evidence="operator training complete"
            if getattr(reg, "operator_training_complete", False) else None,
    ))

    # ── Goals, anti-goals, threats, constraints from the catalogue ────
    # Catalogue entries are static; instances are stamped with whether the
    # current registry satisfies them.
    model.goals       = list(CANONICAL_GOALS)
    model.anti_goals  = list(CANONICAL_ANTI_GOALS)
    model.threats     = list(CANONICAL_THREATS)
    model.constraints = []
    for c in CANONICAL_CONSTRAINTS:
        # Evaluate the constraint against the registry / derived terms
        is_ok, why_not = _evaluate_constraint(c.constraint_id, reg, derived_terms)
        instance = SecurityConstraint(
            constraint_id=c.constraint_id,
            name=c.name,
            description=c.description,
            imposed_by=c.imposed_by,
            on_dependency=c.on_dependency,
            condition=c.condition,
            because=c.because,
            pcs_term=c.pcs_term,
            standard_refs=list(c.standard_refs),
            is_satisfied=is_ok,
            why_unsatisfied=why_not,
        )
        model.constraints.append(instance)

    return model


def _evaluate_constraint(constraint_id: str, reg, derived) -> Tuple[bool, str]:
    """Check whether the current registry satisfies a named constraint.

    Each constraint is a small function — kept inline as a dispatch table
    so the catalogue stays declarative.
    """
    def _get(name, default=None):
        return getattr(reg, name, default)

    if constraint_id == "SC-RCF-1":
        # Trainer and validator must be distinct natural persons
        if _get("trainer_is_validator", False):
            return (False, "trainer_is_validator = True — same physical actor")
        return (True, "")

    if constraint_id == "SC-RCF-2":
        # Validator and deployer must be distinct
        if _get("validator_is_deployer", False):
            return (False, "validator_is_deployer = True — same physical actor")
        return (True, "")

    if constraint_id == "SC-HITL-1":
        if not _get("hitl_formally_specified", False):
            return (False, "hitl_formally_specified = False — no documented HITL plan")
        return (True, "")

    if constraint_id == "SC-DPIA-1":
        if not _get("dpia_approved", False):
            return (False, "dpia_approved = False — DPIA not on file")
        return (True, "")

    if constraint_id == "SC-DOMAIN-1":
        # PINN models require an active domain rule
        from framework.enums import ModelTypeEnum
        if _get("model_type") == ModelTypeEnum.PINN and not _get("domain_rule_active", False):
            return (False, "PINN model declared but domain_rule_active = False")
        return (True, "")

    if constraint_id == "SC-TRAIN-1":
        if not _get("operator_training_complete", False):
            return (False, "operator_training_complete = False — operators untrained")
        return (True, "")

    if constraint_id == "SC-HALLU-1":
        if not _get("hallucination_constraint_declared", False):
            return (False, "hallucination_constraint_declared = False")
        return (True, "")

    if constraint_id == "SC-LIAB-1":
        if not _get("liability_boundary_declared", False):
            return (False, "liability_boundary_declared = False")
        return (True, "")

    if constraint_id == "SC-CHALL-1":
        if not _get("right_to_challenge_documented", False):
            return (False, "right_to_challenge_documented = False")
        return (True, "")

    if constraint_id == "SC-MC-1":
        if not _get("model_card_approved", False):
            return (False, "model_card_approved = False")
        return (True, "")

    if constraint_id == "SC-MAP-1":
        # Mirror the rule-engine SC-MAP-1 trigger: applies when the
        # deployment processes special-category data OR makes
        # CRITICAL / SAFETY_CRITICAL decisions; unsatisfied if either the
        # fairness/bias metric or the output-validation gate is missing.
        # Value-string comparison keeps this module free of enum imports.
        _sens = _get("data_sensitivity")
        _crit = _get("ai_criticality")
        _sens_v = getattr(_sens, "value", _sens)
        _crit_v = getattr(_crit, "value", _crit)
        _applies = (_sens_v == "SPECIAL_CATEGORY") or \
                   (_crit_v in ("CRITICAL", "SAFETY_CRITICAL"))
        if _applies:
            _gaps = []
            if _get("bias_metric") is None:
                _gaps.append("no fairness/bias metric declared")
            if not _get("output_validation_gate_configured", False):
                _gaps.append("no OutputValidationGate configured")
            if _gaps:
                return (False, "; ".join(_gaps))
        return (True, "")

    if constraint_id == "SC-CONSENT-1":
        if not _get("signed_at_collection", False):
            return (False, "signed_at_collection = False — consent provenance missing")
        return (True, "")

    # Unknown constraint — treat as informational (satisfied by default)
    return (True, "")