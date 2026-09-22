// Declarative per-node-type field descriptors — the "variables" pattern
// ported from the Secure Tropos node_concepts.class.js catalogue. The
// Inspector panel is a generic renderer over this table, and it is the
// same target shape a future chatbot fills in: both are front-ends over
// one node schema instead of two hand-maintained ones.
import type { ReactNode } from "react";
import type {
  ActorNodeData,
  AIModelNodeData,
  ConsentRecordNodeData,
  ConstraintCatalogueEntry,
  ConstraintNodeData,
  DataCategoryNodeData,
  DepartmentNodeData,
  DeploymentEnvNodeData,
  LegalBasisNodeData,
  NodeKind,
  RegulatoryReqNodeData,
  TrainingDatasetNodeData,
} from "./types";
import {
  ACTOR_SUBTYPES,
  AI_CRITICALITIES,
  ALL_CONSTRAINT_IDS,
  CATEGORY_SENSITIVITIES,
  CONSTRAINT_STATUSES,
  DATA_SENSITIVITIES,
  HOSTING_ENVIRONMENTS,
  LEGAL_BASIS_VALUES,
  MODEL_TYPES,
  VALIDATION_SOURCES,
} from "./types";

export interface RenderCtx {
  catalogue: ConstraintCatalogueEntry[];
  departments: { id: string; name: string }[];
}

export type FieldDescriptor<D> =
  | {
      key: keyof D & string;
      label: string;
      kind: "select";
      options: readonly string[];
      optionLabels?: Record<string, string>;
    }
  | {
      key: keyof D & string;
      label: string;
      kind: "text";
      placeholder?: string;
    }
  | {
      key: keyof D & string;
      label: string;
      kind: "textarea";
      placeholder?: (data: D) => string;
      helper?: (data: D) => string | null;
    }
  | {
      key: keyof D & string;
      label: string;
      kind: "status-buttons";
      options: readonly string[];
      optionLabels: Record<string, string>;
      variant: Record<string, string>;
    }
  | {
      key: keyof D & string;
      label: string;
      kind: "dynamic-select";
      emptyLabel: string;
      dynamicOptions: (
        ctx: RenderCtx,
        selfNodeId: string
      ) => { value: string; label: string }[];
    };

export interface NodeTypeDescriptor<D> {
  kickerClass: string;
  kicker: (data: D) => string;
  heading: (data: D) => string;
  fields: FieldDescriptor<D>[];
  renderMeta?: (data: D, ctx: RenderCtx) => ReactNode;
  footnote: ReactNode;
}

const TITLE_CASE: Record<string, string> = {
  TRAINER: "Trainer",
  VALIDATOR: "Validator",
  DEPLOYER: "Deployer",
  OPERATOR: "Operator",
  CONSUMER: "Consumer",
};

const STATUS_LABEL: Record<string, string> = {
  NOT_YET_DETERMINED: "Not Yet Det.",
  UNMET: "Unmet",
  SATISFIED: "Satisfied",
};

const STATUS_VARIANT: Record<string, string> = {
  NOT_YET_DETERMINED: "pending",
  UNMET: "unmet",
  SATISFIED: "satisfied",
};

const actorDescriptor: NodeTypeDescriptor<ActorNodeData> = {
  kickerClass: "actor",
  kicker: (d) => `Actor · ${TITLE_CASE[d.subtype]}`,
  heading: (d) => TITLE_CASE[d.subtype],
  fields: [
    {
      key: "subtype",
      label: "Subtype",
      kind: "select",
      options: ACTOR_SUBTYPES,
      optionLabels: TITLE_CASE,
    },
    {
      key: "identity",
      label: "Identity",
      kind: "text",
      placeholder: "e.g. Data Science ML Team",
    },
    {
      key: "departmentId",
      label: "Department",
      kind: "dynamic-select",
      emptyLabel: "— None —",
      dynamicOptions: (ctx) =>
        ctx.departments.map((d) => ({ value: d.id, label: d.name })),
    },
  ],
  footnote: (
    <>
      Drag an actor onto a department box on the canvas to nest it, or set
      its department here directly. Connect an actor to a constraint to
      create an <code>on_dependency</code> edge.
    </>
  ),
};

const departmentDescriptor: NodeTypeDescriptor<DepartmentNodeData> = {
  kickerClass: "department",
  kicker: () => "Department",
  heading: (d) => d.name || "(unnamed department)",
  fields: [
    {
      key: "name",
      label: "Name",
      kind: "text",
      placeholder: "e.g. Data Science",
    },
    {
      key: "reportsToDepartmentId",
      label: "Reports to",
      kind: "dynamic-select",
      emptyLabel: "— None (top-level) —",
      dynamicOptions: (ctx, selfId) =>
        ctx.departments
          .filter((d) => d.id !== selfId)
          .map((d) => ({ value: d.id, label: d.name })),
    },
  ],
  footnote: (
    <>
      Departments become <code>registry.departments</code> entries. Drag
      Actor nodes inside this box to set their department automatically.
    </>
  ),
};

const MODEL_TYPE_LABEL: Record<string, string> = {
  LLM: "LLM",
  NN: "Neural Network",
  CNN: "CNN",
  RL: "Reinforcement Learning",
  ENSEMBLE: "Ensemble",
  HYBRID: "Hybrid",
  PINN: "Physics-Informed NN",
};

const AI_CRITICALITY_LABEL: Record<string, string> = {
  ADVISORY: "Advisory",
  OPERATIONAL: "Operational",
  CRITICAL: "Critical",
  SAFETY_CRITICAL: "Safety-Critical",
};

const DATA_SENSITIVITY_LABEL: Record<string, string> = {
  PUBLIC: "Public",
  INTERNAL: "Internal",
  CONFIDENTIAL: "Confidential",
  SENSITIVE_PERSONAL: "Sensitive Personal",
  SPECIAL_CATEGORY: "Special Category",
};

const HOSTING_LABEL: Record<string, string> = {
  TYPE_1_INHOUSE: "In-house",
  TYPE_2_FINETUNED: "Fine-tuned",
  TYPE_3_THIRDPARTY_API: "Third-party API",
};

const aiModelDescriptor: NodeTypeDescriptor<AIModelNodeData> = {
  kickerClass: "ai-model",
  kicker: (d) => `AI Model · ${MODEL_TYPE_LABEL[d.modelType]}`,
  heading: (d) => d.name || "(unnamed model)",
  fields: [
    {
      key: "name",
      label: "Name",
      kind: "text",
      placeholder: "e.g. Clinical Triage LLM",
    },
    {
      key: "modelType",
      label: "Model Type",
      kind: "select",
      options: MODEL_TYPES,
      optionLabels: MODEL_TYPE_LABEL,
    },
    {
      key: "aiCriticality",
      label: "Criticality",
      kind: "select",
      options: AI_CRITICALITIES,
      optionLabels: AI_CRITICALITY_LABEL,
    },
    {
      key: "domain",
      label: "Domain",
      kind: "text",
      placeholder: "e.g. Healthcare, Finance, Employment",
    },
    {
      key: "dataSensitivity",
      label: "Data Sensitivity",
      kind: "select",
      options: DATA_SENSITIVITIES,
      optionLabels: DATA_SENSITIVITY_LABEL,
    },
    {
      key: "hostingEnvironment",
      label: "Hosting Environment",
      kind: "select",
      options: HOSTING_ENVIRONMENTS,
      optionLabels: HOSTING_LABEL,
    },
  ],
  footnote: (
    <>
      Populates <code>registry.deployment_context</code> and{" "}
      <code>registry.system_type</code>. Only the first AI Model node on
      canvas feeds a score — the registry has one deployment context.
    </>
  ),
};

const constraintDescriptor: NodeTypeDescriptor<ConstraintNodeData> = {
  kickerClass: "constraint",
  kicker: () => "Security Constraint",
  heading: (d) => d.constraintId,
  fields: [
    {
      key: "constraintId",
      label: "Constraint ID",
      kind: "select",
      options: ALL_CONSTRAINT_IDS,
    },
    {
      key: "status",
      label: "Status",
      kind: "status-buttons",
      options: CONSTRAINT_STATUSES,
      optionLabels: STATUS_LABEL,
      variant: STATUS_VARIANT,
    },
    {
      key: "evidence",
      label: "Evidence",
      kind: "textarea",
      placeholder: (d) =>
        d.status === "SATISFIED"
          ? "Required — SATISFIED status is rejected server-side without evidence"
          : "Optional",
      helper: (d) =>
        d.status === "SATISFIED" ? "(required to mark Satisfied)" : null,
    },
  ],
  renderMeta: (d, ctx) => {
    const meta = ctx.catalogue.find((c) => c.constraint_id === d.constraintId);
    if (!meta) return null;
    return (
      <p className="ai-field__meta">
        <strong>{meta.class === "veto" ? "Veto class" : "Modulating"}</strong>
        {meta.name ? ` — ${meta.name}` : ""}
      </p>
    );
  },
  footnote: (
    <>
      Veto-class constraints can only reach Satisfied with non-empty evidence
      — enforced server-side on every <code>/score</code> call.
    </>
  ),
};

const CATEGORY_SENSITIVITY_LABEL: Record<string, string> = {
  NON_PERSONAL: "Non-personal",
  PERSONAL: "Personal",
  SPECIAL_CATEGORY: "Special Category",
};

const dataCategoryDescriptor: NodeTypeDescriptor<DataCategoryNodeData> = {
  kickerClass: "data-category",
  kicker: () => "Data Category",
  heading: (d) => d.name || "(unnamed category)",
  fields: [
    {
      key: "name",
      label: "Name",
      kind: "text",
      placeholder: "e.g. Patient diagnostic records",
    },
    {
      key: "sensitivity",
      label: "Sensitivity",
      kind: "select",
      options: CATEGORY_SENSITIVITIES,
      optionLabels: CATEGORY_SENSITIVITY_LABEL,
    },
  ],
  footnote: (
    <>
      Becomes a <code>registry.data_categories</code> entry. Connect a
      Consent Record to reference it.
    </>
  ),
};

const VALIDATION_SOURCE_LABEL: Record<string, string> = {
  MANUAL: "Manual",
  DIAPROD_API: "DiaProd API",
};

const consentRecordDescriptor: NodeTypeDescriptor<ConsentRecordNodeData> = {
  kickerClass: "consent-record",
  kicker: () => "Consent Record",
  heading: (d) => d.diaprodConsentId || "(unnamed consent record)",
  fields: [
    {
      key: "diaprodConsentId",
      label: "Consent ID",
      kind: "text",
      placeholder: "e.g. DIAPROD-2026-0143",
    },
    {
      key: "validatedAt",
      label: "Validated At",
      kind: "text",
      placeholder: "e.g. 2026-01-15",
    },
    {
      key: "validationSource",
      label: "Validation Source",
      kind: "select",
      options: VALIDATION_SOURCES,
      optionLabels: VALIDATION_SOURCE_LABEL,
    },
  ],
  footnote: (
    <>
      Becomes a <code>registry.consent_records</code> entry. Connect it to a
      Legal Basis node to set its legal basis, and to Data Category nodes to
      set which categories it covers.
    </>
  ),
};

const regulatoryReqDescriptor: NodeTypeDescriptor<RegulatoryReqNodeData> = {
  kickerClass: "regulatory-req",
  kicker: () => "Regulatory Requirement",
  heading: (d) => d.instrument || "(unnamed requirement)",
  fields: [
    {
      key: "instrument",
      label: "Instrument",
      kind: "text",
      placeholder: "e.g. GDPR, EU AI Act",
    },
    {
      key: "clause",
      label: "Clause",
      kind: "text",
      placeholder: "e.g. Art. 22",
    },
    {
      key: "riskTier",
      label: "Risk Tier",
      kind: "text",
      placeholder: "e.g. HIGH",
    },
    {
      key: "status",
      label: "Status",
      kind: "status-buttons",
      options: CONSTRAINT_STATUSES,
      optionLabels: STATUS_LABEL,
      variant: STATUS_VARIANT,
    },
  ],
  footnote: (
    <>
      Becomes a <code>registry.regulatory_requirements</code> entry. Connect
      it to a Constraint node it requires, or to the AI Model it covers.
    </>
  ),
};

const LEGAL_BASIS_LABEL: Record<string, string> = {
  CONSENT: "Consent",
  CONTRACT: "Contract",
  LEGAL_OBLIGATION: "Legal Obligation",
  VITAL_INTERESTS: "Vital Interests",
  PUBLIC_TASK: "Public Task",
  LEGITIMATE_INTERESTS: "Legitimate Interests",
};

const legalBasisDescriptor: NodeTypeDescriptor<LegalBasisNodeData> = {
  kickerClass: "legal-basis",
  kicker: () => "Legal Basis",
  heading: (d) => LEGAL_BASIS_LABEL[d.basis],
  fields: [
    {
      key: "basis",
      label: "GDPR Art. 6(1) Basis",
      kind: "select",
      options: LEGAL_BASIS_VALUES,
      optionLabels: LEGAL_BASIS_LABEL,
    },
  ],
  footnote: (
    <>
      schema.py has no dedicated Legal Basis entity — connecting this to a
      Consent Record sets that record's <code>legal_basis</code> text field.
    </>
  ),
};

const trainingDatasetDescriptor: NodeTypeDescriptor<TrainingDatasetNodeData> = {
  kickerClass: "training-dataset",
  kicker: () => "Training Dataset",
  heading: (d) => d.name || "(unnamed dataset)",
  fields: [
    { key: "name", label: "Name", kind: "text", placeholder: "e.g. Triage-2026-Q1" },
    { key: "description", label: "Description", kind: "textarea" },
  ],
  footnote: (
    <>
      Presentational only — schema.py has no registry-level field for
      datasets yet, so this doesn't feed <code>/score</code>. Connect it to
      an AI Model to document what it was trained on.
    </>
  ),
};

const deploymentEnvDescriptor: NodeTypeDescriptor<DeploymentEnvNodeData> = {
  kickerClass: "deployment-env",
  kicker: () => "Deployment Environment",
  heading: (d) => d.name || "(unnamed environment)",
  fields: [
    { key: "name", label: "Name", kind: "text", placeholder: "e.g. AWS eu-west-1 prod" },
    { key: "description", label: "Description", kind: "textarea" },
  ],
  footnote: (
    <>
      Presentational only — schema.py has no registry-level field for
      deployment environments yet, so this doesn't feed <code>/score</code>.
      Connect it to an AI Model to document where it runs.
    </>
  ),
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const NODE_SCHEMA: Partial<Record<NodeKind, NodeTypeDescriptor<any>>> = {
  ACTOR: actorDescriptor,
  CONSTRAINT: constraintDescriptor,
  DEPARTMENT: departmentDescriptor,
  AI_MODEL: aiModelDescriptor,
  DATA_CATEGORY: dataCategoryDescriptor,
  CONSENT_RECORD: consentRecordDescriptor,
  REGULATORY_REQ: regulatoryReqDescriptor,
  LEGAL_BASIS: legalBasisDescriptor,
  TRAINING_DATASET: trainingDatasetDescriptor,
  DEPLOYMENT_ENV: deploymentEnvDescriptor,
};
