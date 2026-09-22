// Declarative per-node-type field descriptors — the "variables" pattern
// ported from the Secure Tropos node_concepts.class.js catalogue. The
// Inspector panel is a generic renderer over this table, and it is the
// same target shape a future chatbot fills in: both are front-ends over
// one node schema instead of two hand-maintained ones.
import type { ReactNode } from "react";
import type {
  ActorNodeData,
  ConstraintCatalogueEntry,
  ConstraintNodeData,
  DepartmentNodeData,
  NodeKind,
} from "./types";
import {
  ACTOR_SUBTYPES,
  ALL_CONSTRAINT_IDS,
  CONSTRAINT_STATUSES,
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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const NODE_SCHEMA: Partial<Record<NodeKind, NodeTypeDescriptor<any>>> = {
  ACTOR: actorDescriptor,
  CONSTRAINT: constraintDescriptor,
  DEPARTMENT: departmentDescriptor,
};
