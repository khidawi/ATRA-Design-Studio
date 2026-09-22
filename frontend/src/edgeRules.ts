// The canvas analogue of Secure Tropos's metamodel.views[i].relations: a
// small table of which EdgeType (schema.py) applies between which node
// type/subtype pair, and in which canonical direction — regardless of
// which node the user actually dragged from. Falls back to the generic
// ON_DEPENDENCY relation for any pair with no specific rule, so connecting
// two node types nothing below knows about is never blocked.
import type { ActorNodeData, ActorSubtype, CanvasNodeData } from "./types";

export type EdgeTypeName =
  | "ON_DEPENDENCY"
  | "IMPOSED_BY"
  | "BELONGS_TO"
  | "TRAINS"
  | "VALIDATES"
  | "DEPLOYS"
  | "OPERATES"
  | "CONSUMED_BY"
  | "REPORTS_TO";

interface EdgeRule {
  // True when (from -> to), in exactly this order, is the relation's
  // canonical direction.
  match: (from: CanvasNodeData, to: CanvasNodeData) => boolean;
  type: EdgeTypeName;
  label: string;
}

function isActor(d: CanvasNodeData, subtype?: ActorSubtype): d is ActorNodeData {
  return d.kind === "ACTOR" && (!subtype || d.subtype === subtype);
}

const RULES: EdgeRule[] = [
  {
    match: (f, t) => isActor(f, "TRAINER") && t.kind === "AI_MODEL",
    type: "TRAINS",
    label: "trains",
  },
  {
    match: (f, t) => isActor(f, "VALIDATOR") && t.kind === "AI_MODEL",
    type: "VALIDATES",
    label: "validates",
  },
  {
    match: (f, t) => isActor(f, "DEPLOYER") && t.kind === "AI_MODEL",
    type: "DEPLOYS",
    label: "deploys",
  },
  {
    match: (f, t) => isActor(f, "OPERATOR") && t.kind === "AI_MODEL",
    type: "OPERATES",
    label: "operates",
  },
  {
    match: (f, t) => f.kind === "AI_MODEL" && isActor(t, "CONSUMER"),
    type: "CONSUMED_BY",
    label: "consumed_by",
  },
  {
    match: (f, t) => f.kind === "CONSTRAINT" && isActor(t),
    type: "IMPOSED_BY",
    label: "imposed_by",
  },
  {
    match: (f, t) => isActor(f) && t.kind === "DEPARTMENT",
    type: "BELONGS_TO",
    label: "belongs_to",
  },
  {
    match: (f, t) => f.kind === "DEPARTMENT" && t.kind === "DEPARTMENT",
    type: "REPORTS_TO",
    label: "reports_to",
  },
];

export interface ResolvedEdge {
  type: EdgeTypeName;
  label: string;
  /** True when source/target must be swapped to match the canonical direction. */
  swapped: boolean;
}

export function resolveEdge(
  sourceData: CanvasNodeData,
  targetData: CanvasNodeData
): ResolvedEdge {
  for (const rule of RULES) {
    if (rule.match(sourceData, targetData)) {
      return { type: rule.type, label: rule.label, swapped: false };
    }
    if (rule.match(targetData, sourceData)) {
      return { type: rule.type, label: rule.label, swapped: true };
    }
  }
  return { type: "ON_DEPENDENCY", label: "on_dependency", swapped: false };
}
