"""
Removing an AI agent or an AI model from the platform (Task 15).

The organisation, AI Agents and AI Models are one platform, so removing an agent or a model removes it everywhere:

  agent  - its inventory entry, its designs, every contract issued for it, its findings, its drift items, its runtime events, and its place
           in the organisation (the node and every connection to it);
  model  - its place in the organisation, AI Models designs that were started from it, and the contracts compiled from those designs.

Evidence packs are point-in-time records that cite contracts by id and hash, so a pack must stay verifiable after a contract is removed:
each removed contract leaves a small tombstone (id, hash, who removed it and when) and verifying a pack reports it as removed, not as tampered with.
The audit log records every removal with what it took. Only an administrator may remove an agent or a model.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

import audit
from agent_registry import agent_key as to_agent_key
from auth import AuthUser, current_user
from db.models import Agent, CompanyEdge, CompanyNode, Contract, Design, DriftItem, Finding, RemovedContract, RuntimeEvent
from db.session import get_session
from organisation import current_organisation

router = APIRouter(prefix="/api/agents", tags=["removal"])


def node_key(node: CompanyNode) -> str:
    return (node.props or {}).get("agent_key") or to_agent_key(node.name)


def org_agent_node(session: Session, org_id: Any, key: str) -> Optional[CompanyNode]:
    for n in session.scalars(select(CompanyNode).where(CompanyNode.organisation_id == org_id, CompanyNode.type == "agent")):
        if node_key(n) == key:
            return n
    return None


def agent_designs(session: Session, key: str) -> List[Design]:
    """The designs of an agent: the one its inventory entry points at, and any agent design whose primary agent has this name."""
    out: Dict[Any, Design] = {}
    a = session.scalar(select(Agent).where(Agent.agent_key == key))
    if a is not None and a.design_id:
        d = session.get(Design, a.design_id)
        if d is not None:
            out[d.id] = d
    for d in session.scalars(select(Design).where(Design.subject == "AGENT")):
        primary = next((n for n in (d.document or {}).get("nodes", []) if n.get("primary") and n.get("type") == "agent"), None)
        if primary and to_agent_key(str(primary.get("name", ""))) == key:
            out[d.id] = d
    return list(out.values())


def model_designs(session: Session, ext_id: str) -> List[Design]:
    """The AI Models designs that were started from this organisation model (they remember it in their document)."""
    return [d for d in session.scalars(select(Design).where(Design.subject == "MODEL")) if ((d.document or {}).get("org") or {}).get("id") == ext_id]


def _count(session: Session, model: Any, *where: Any) -> int:
    return session.scalar(select(func.count()).select_from(model).where(*where)) or 0


def agent_impact(session: Session, key: str) -> Dict[str, Any]:
    org = current_organisation(session)
    a = session.scalar(select(Agent).where(Agent.agent_key == key))
    node = org_agent_node(session, org.id, key)
    if a is None and node is None:
        raise HTTPException(status_code=404, detail="No such agent.")
    designs = agent_designs(session, key)
    edges = 0
    if node is not None:
        edges = _count(session, CompanyEdge, CompanyEdge.organisation_id == org.id, (CompanyEdge.from_ext == node.ext_id) | (CompanyEdge.to_ext == node.ext_id))
    return {"agent_key": key, "name": a.name if a else node.name, "in_inventory": a is not None, "in_organisation": node is not None,
            "designs": len(designs), "contracts": _count(session, Contract, Contract.object_type == "AGENT", Contract.deployment_id == key),
            "findings": _count(session, Finding, Finding.agent_key == key), "drift_items": _count(session, DriftItem, DriftItem.agent_key == key),
            "runtime_events": _count(session, RuntimeEvent, RuntimeEvent.agent_key == key), "organisation_connections": edges}


def model_impact(session: Session, ext_id: str) -> Dict[str, Any]:
    org = current_organisation(session)
    node = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == ext_id, CompanyNode.type == "model"))
    if node is None:
        raise HTTPException(status_code=404, detail="That model is not in the organisation.")
    designs = model_designs(session, ext_id)
    ids = [d.id for d in designs]
    return {"id": ext_id, "name": node.name, "designs": len(designs), "contracts": _count(session, Contract, Contract.design_id.in_(ids)) if ids else 0,
            "organisation_connections": _count(session, CompanyEdge, CompanyEdge.organisation_id == org.id, (CompanyEdge.from_ext == ext_id) | (CompanyEdge.to_ext == ext_id))}


def _bury_contracts(session: Session, contracts: List[Contract], user: AuthUser, why: str) -> None:
    for c in contracts:
        session.add(RemovedContract(contract_id=c.contract_id, object_type=c.object_type, deployment_id=c.deployment_id, version=str((c.document or {}).get("version", "")),
                                    contract_hash=c.contract_hash, removed_by=user.name, reason=why[:200]))
        session.delete(c)


def remove_agent(session: Session, key: str, user: AuthUser) -> Dict[str, Any]:
    """Removes an agent everywhere. Returns what was removed; commits."""
    import company
    impact = agent_impact(session, key)
    org = current_organisation(session)
    why = f"Agent {impact['name']} was removed from the platform"
    _bury_contracts(session, list(session.scalars(select(Contract).where(Contract.object_type == "AGENT", Contract.deployment_id == key))), user, why)
    session.flush()
    for d in agent_designs(session, key):
        session.delete(d)
    session.execute(delete(Finding).where(Finding.agent_key == key))
    session.execute(delete(DriftItem).where(DriftItem.agent_key == key))
    session.execute(delete(RuntimeEvent).where(RuntimeEvent.agent_key == key))
    a = session.scalar(select(Agent).where(Agent.agent_key == key))
    if a is not None:
        session.delete(a)
    node = org_agent_node(session, org.id, key)
    if node is not None:
        company.drop_node(session, org, node)
    session.commit()
    audit.record(user.name, user.role, "agent.removed", "ok", impact)
    return impact


def remove_model(session: Session, ext_id: str, user: AuthUser) -> Dict[str, Any]:
    """Removes an organisation model, AI Models designs started from it, and the contracts compiled from them. Commits."""
    import company
    impact = model_impact(session, ext_id)
    org = current_organisation(session)
    designs = model_designs(session, ext_id)
    ids = [d.id for d in designs]
    if ids:
        _bury_contracts(session, list(session.scalars(select(Contract).where(Contract.design_id.in_(ids)))), user, f"Model {impact['name']} was removed from the platform")
        session.flush()
    for d in designs:
        session.delete(d)
    node = session.scalar(select(CompanyNode).where(CompanyNode.organisation_id == org.id, CompanyNode.ext_id == ext_id))
    if node is not None:
        company.drop_node(session, org, node)
    session.commit()
    audit.record(user.name, user.role, "model.removed", "ok", impact)
    return impact


@router.get("/{key}/removal-impact")
def removal_impact(key: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """What removing this agent would take with it, for the confirmation."""
    return agent_impact(session, key)


@router.delete("/{key}")
def delete_agent(key: str, session: Session = Depends(get_session), user: AuthUser = Depends(current_user)) -> Dict[str, Any]:
    """Removes the agent from the whole platform. Administrators only (see auth.required_permission)."""
    return remove_agent(session, key, user)
