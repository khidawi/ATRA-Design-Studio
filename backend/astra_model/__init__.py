"""
The ASTRA formal model for AI agents, as pure functions (no database, no network).

    estate      departments, agents, resources, delegation, tolerance
    exposure    attack paths and the controls each needs
    statuses    control statuses, evidence, expiry
    gate        the verdict and the department risk vector
    classes     the 22 divergence classes of the specification (data)
    events      the conformity predicate for runtime events
    contract    canonical form, hash, Ed25519 signature, validity

The rules that matter, each tested in tests/test_astra_model.py:
    * the gate is monotone: worse evidence never improves a verdict;
    * a learned detector can only move the baseline control to UNVERIFIED;
    * an event with a missing attribute is never read as conforming;
    * INVALID_CONTRACT outranks every other verdict.
"""
from . import classes, contract, estate, events, exposure, gate, statuses

__all__ = ["classes", "contract", "estate", "events", "exposure", "gate", "statuses"]
