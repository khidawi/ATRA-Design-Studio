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

// Backend enum values (framework/enums.py) — kept in sync by hand since
// schema.py's DeploymentContext only types these as plain `str`.
export type ModelType = "NN" | "RL" | "ENSEMBLE" | "PINN" | "LLM" | "CNN" | "HYBRID";
export const MODEL_TYPES: ModelType[] = [
  "LLM",
  "NN",
  "CNN",
  "RL",
  "ENSEMBLE",
  "HYBRID",
  "PINN",
];

export type AICriticality =
  | "ADVISORY"
  | "OPERATIONAL"
  | "CRITICAL"
  | "SAFETY_CRITICAL";
export const AI_CRITICALITIES: AICriticality[] = [
  "ADVISORY",
  "OPERATIONAL",
  "CRITICAL",
  "SAFETY_CRITICAL",
];

export type DataSensitivity =
  | "PUBLIC"
  | "INTERNAL"
  | "CONFIDENTIAL"
  | "SENSITIVE_PERSONAL"
  | "SPECIAL_CATEGORY";
export const DATA_SENSITIVITIES: DataSensitivity[] = [
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "SENSITIVE_PERSONAL",
  "SPECIAL_CATEGORY",
];

export type HostingEnvironment =
  | "TYPE_1_INHOUSE"
  | "TYPE_2_FINETUNED"
  | "TYPE_3_THIRDPARTY_API";
export const HOSTING_ENVIRONMENTS: HostingEnvironment[] = [
  "TYPE_1_INHOUSE",
  "TYPE_2_FINETUNED",
  "TYPE_3_THIRDPARTY_API",
];

export interface AIModelNodeData {
  kind: "AI_MODEL";
  name: string;
  modelType: ModelType;
  aiCriticality: AICriticality;
  domain: string;
  dataSensitivity: DataSensitivity;
  hostingEnvironment: HostingEnvironment;
}

// DataCategory.sensitivity uses its own 3-value vocabulary in schema.py —
// distinct from DeploymentContext's 5-value DataSensitivity above.
export type CategorySensitivity = "NON_PERSONAL" | "PERSONAL" | "SPECIAL_CATEGORY";
export const CATEGORY_SENSITIVITIES: CategorySensitivity[] = [
  "NON_PERSONAL",
  "PERSONAL",
  "SPECIAL_CATEGORY",
];

export interface DataCategoryNodeData {
  kind: "DATA_CATEGORY";
  name: string;
  sensitivity: CategorySensitivity;
}

export type ValidationSource = "MANUAL" | "DIAPROD_API";
export const VALIDATION_SOURCES: ValidationSource[] = ["MANUAL", "DIAPROD_API"];

export interface ConsentRecordNodeData {
  kind: "CONSENT_RECORD";
  diaprodConsentId: string;
  validatedAt: string;
  validationSource: ValidationSource;
}

export interface RegulatoryReqNodeData {
  kind: "REGULATORY_REQ";
  instrument: string;
  clause: string;
  riskTier: string;
  status: ConstraintStatus;
}

// GDPR Art. 6(1) legal bases — the standard six, since schema.py's
// ConsentRecord.legal_basis is free text with no backend-defined enum.
export type LegalBasisValue =
  | "CONSENT"
  | "CONTRACT"
  | "LEGAL_OBLIGATION"
  | "VITAL_INTERESTS"
  | "PUBLIC_TASK"
  | "LEGITIMATE_INTERESTS";
export const LEGAL_BASIS_VALUES: LegalBasisValue[] = [
  "CONSENT",
  "CONTRACT",
  "LEGAL_OBLIGATION",
  "VITAL_INTERESTS",
  "PUBLIC_TASK",
  "LEGITIMATE_INTERESTS",
];

export interface LegalBasisNodeData {
  kind: "LEGAL_BASIS";
  basis: LegalBasisValue;
}

// TRAINING_DATASET and DEPLOYMENT_ENV have no corresponding registry-level
// model in schema.py (RegistryBlock has no such lists) — they're purely
// presentational canvas nodes today, same as the graph itself. Useful for
// documenting the deployment visually (AI_MODEL --trained_on/runs_in-->)
// even though they don't feed /score yet.
export interface TrainingDatasetNodeData {
  kind: "TRAINING_DATASET";
  name: string;
  description: string;
}

export interface DeploymentEnvNodeData {
  kind: "DEPLOYMENT_ENV";
  name: string;
  description: string;
}

export type CanvasNodeData =
  | ActorNodeData
  | ConstraintNodeData
  | DepartmentNodeData
  | AIModelNodeData
  | DataCategoryNodeData
  | ConsentRecordNodeData
  | RegulatoryReqNodeData
  | LegalBasisNodeData
  | TrainingDatasetNodeData
  | DeploymentEnvNodeData;

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
  deployment_context?: {
    model_type: ModelType;
    ai_criticality: AICriticality;
    data_sensitivity: DataSensitivity;
    domain: string;
  };
  system_type?: HostingEnvironment;
  data_categories: { id: string; name: string; sensitivity: CategorySensitivity }[];
  consent_records: {
    id: string;
    diaprod_consent_id?: string;
    legal_basis: string;
    data_category_ids: string[];
    validated_at?: string;
    validation_source?: ValidationSource;
  }[];
  regulatory_requirements: {
    id: string;
    instrument: string;
    clause: string;
    risk_tier?: string;
    status: ConstraintStatus;
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

// ── /chat request / response ───────────────────────────────────────────────

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface GeneratedDepartment {
  temp_id: string;
  name: string;
  reports_to_temp_id?: string | null;
}

export interface GeneratedActor {
  temp_id: string;
  subtype: ActorSubtype;
  identity: string;
  department_temp_id?: string | null;
}

export interface GeneratedAIModel {
  temp_id: string;
  name: string;
  model_type: ModelType;
  ai_criticality: AICriticality;
  domain: string;
  data_sensitivity: DataSensitivity;
  hosting_environment: HostingEnvironment;
}

export interface GeneratedDeploymentEnv {
  temp_id: string;
  name: string;
  description: string;
}

export interface GeneratedConstraint {
  temp_id: string;
  constraint_id: string;
  status: ConstraintStatus;
  evidence: string;
}

export interface GeneratedEdge {
  from_temp_id: string;
  to_temp_id: string;
}

export interface GeneratedGraph {
  reply: string;
  departments: GeneratedDepartment[];
  actors: GeneratedActor[];
  ai_models: GeneratedAIModel[];
  deployment_environments: GeneratedDeploymentEnv[];
  constraints: GeneratedConstraint[];
  edges: GeneratedEdge[];
}

// ── POST /api/designs/import request body ──────────────────────────────────
// Mirrors backend/compliance_schema.py's DeploymentDescription. Structural
// fields only, on purpose — there is no field here for constraint/veto
// status, so an imported JSON cannot claim DPIA/HITL/etc. are satisfied.

export interface DeploymentDescriptionPayload {
  schema_version?: string;
  deployment_name?: string;
  description?: string;
  assessment_domain?: string | null;
  departments: {
    temp_id: string;
    name: string;
    reports_to_temp_id?: string | null;
  }[];
  actors: {
    temp_id: string;
    subtype: ActorSubtype;
    identity?: string;
    department_temp_id?: string | null;
  }[];
  ai_models: {
    temp_id: string;
    name: string;
    model_type?: ModelType;
    ai_criticality?: AICriticality;
    data_sensitivity?: DataSensitivity;
    hosting_environment?: HostingEnvironment;
    domain?: string;
  }[];
  deployment_environments: {
    temp_id: string;
    name: string;
    description?: string;
  }[];
}
