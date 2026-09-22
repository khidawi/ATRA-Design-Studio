// Mirrors the relevant slice of backend/schema.py. Only ACTOR + CONSTRAINT
// node types and the ON_DEPENDENCY edge type are wired up in the UI so far;
// the remaining NodeType members exist so the palette can grow into them.

export type NodeKind =
  | "ACTOR"
  | "DEPARTMENT"
  | "AI_MODEL"
  | "TRAINING_DATASET"
  | "DEPLOYMENT_ENV"
  | "CONSTRAINT"
  | "CONSENT_RECORD"
  | "LEGAL_BASIS"
  | "REGULATORY_REQ"
  | "DATA_CATEGORY"
  | "MONITORING_SIGNAL"
  | "INCIDENT";

export type ActorSubtype =
  | "TRAINER"
  | "VALIDATOR"
  | "DEPLOYER"
  | "OPERATOR"
  | "CONSUMER";

export const ACTOR_SUBTYPES: ActorSubtype[] = [
  "TRAINER",
  "VALIDATOR",
  "DEPLOYER",
  "OPERATOR",
  "CONSUMER",
];

export type ConstraintStatus = "SATISFIED" | "UNMET" | "NOT_YET_DETERMINED";

export const CONSTRAINT_STATUSES: ConstraintStatus[] = [
  "NOT_YET_DETERMINED",
  "UNMET",
  "SATISFIED",
];

// Copied verbatim from backend/schema.py VETO_CLASS_CONSTRAINTS /
// MODULATING_CLASS_CONSTRAINTS so the canvas can seed a full
// constraints_declared map even before /catalogue/constraints resolves.
export const VETO_CONSTRAINT_IDS = [
  "SC-DPIA-1",
  "SC-HITL-1",
  "SC-HALLU-1",
  "SC-MAP-1",
  "SC-CHALL-1",
  "SC-LIAB-1",
] as const;

export const MODULATING_CONSTRAINT_IDS = [
  "SC-MC-1",
  "SC-TRAIN-1",
  "SC-RCF-1",
  "SC-RCF-2",
  "SC-DOMAIN-1",
  "SC-CONSENT-1",
] as const;

export const ALL_CONSTRAINT_IDS: string[] = [
  ...VETO_CONSTRAINT_IDS,
  ...MODULATING_CONSTRAINT_IDS,
];

export interface ActorNodeData {
  kind: "ACTOR";
  subtype: ActorSubtype;
  identity: string;
  departmentId: string;
}

export interface ConstraintNodeData {
  kind: "CONSTRAINT";
  constraintId: string;
  status: ConstraintStatus;
  evidence: string;
}

export interface DepartmentNodeData {
  kind: "DEPARTMENT";
  name: string;
  reportsToDepartmentId: string;
}

export type CanvasNodeData =
  | ActorNodeData
  | ConstraintNodeData
  | DepartmentNodeData;

export interface ConstraintCatalogueEntry {
  constraint_id: string;
  name: string;
  class: "veto" | "modulating";
  because: string;
  standard_refs: string[];
  actor_role: string | null;
}

// ── /score request / response ──────────────────────────────────────────────

export interface RegistryBlockPayload {
  actors: Partial<
    Record<string, { identity: string; department_id?: string }>
  >;
  departments: {
    id: string;
    name: string;
    reports_to_department_id?: string;
  }[];
  governance_state: {
    constraints_declared: Record<
      string,
      { status: ConstraintStatus; evidence?: string }
    >;
  };
}

export interface PillarVector {
  likelihood: number | null;
  severity: number | null;
  vulnerability: number | null;
  uncertainty: number | null;
  autonomy: number | null;
  evolution: number | null;
}

export interface PCSResultBlock {
  pcs_mult: number | null;
  pcs_floor: number | null;
  pcs_final: number | null;
  tier: string | null;
  gate: string | null;
  pillar_vector: PillarVector;
  unmet_veto_constraints: string[];
  last_scored_at: string | null;
  raw_breakdown: Record<string, unknown> | null;
}

export interface ScoreResponse {
  pcs_result: PCSResultBlock;
  warnings: string[];
}
