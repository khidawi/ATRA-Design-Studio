import type { DragEvent } from "react";
import { CONSTRAINT_BUNDLES } from "../constraintBundles";
import { useCanvasStore } from "../store/useCanvasStore";
import { ACTOR_SUBTYPES, type ActorSubtype, type NodeKind } from "../types";

const TITLE_CASE: Record<ActorSubtype, string> = {
  TRAINER: "Trainer",
  VALIDATOR: "Validator",
  DEPLOYER: "Deployer",
  OPERATOR: "Operator",
  CONSUMER: "Consumer",
};

const SIMPLE_ROWS: { kind: NodeKind; label: string; swatch: string }[] = [
  { kind: "TRAINING_DATASET", label: "Training Dataset", swatch: "training-dataset" },
  { kind: "DEPLOYMENT_ENV", label: "Deployment Environment", swatch: "deployment-env" },
];

const CONSENT_ROWS: { kind: NodeKind; label: string; swatch: string }[] = [
  { kind: "CONSENT_RECORD", label: "Consent Record", swatch: "consent-record" },
  { kind: "LEGAL_BASIS", label: "Legal Basis", swatch: "legal-basis" },
  { kind: "REGULATORY_REQ", label: "Regulatory Requirement", swatch: "regulatory-req" },
  { kind: "DATA_CATEGORY", label: "Data Category", swatch: "data-category" },
];

export default function Sidebar() {
  const nodes = useCanvasStore((s) => s.nodes);
  const addActorNode = useCanvasStore((s) => s.addActorNode);
  const addConstraintNode = useCanvasStore((s) => s.addConstraintNode);
  const addDepartmentNode = useCanvasStore((s) => s.addDepartmentNode);
  const addAIModelNode = useCanvasStore((s) => s.addAIModelNode);
  const addSimpleNode = useCanvasStore((s) => s.addSimpleNode);
  const addConstraintBundle = useCanvasStore((s) => s.addConstraintBundle);

  const nextPosition = () => {
    const i = nodes.length;
    return { x: 80 + (i % 4) * 190, y: 60 + Math.floor(i / 4) * 130 };
  };

  const onActorDragStart = (
    event: DragEvent<HTMLButtonElement>,
    subtype: ActorSubtype
  ) => {
    event.dataTransfer.setData(
      "application/stai-node-kind",
      JSON.stringify({ kind: "ACTOR", subtype })
    );
    event.dataTransfer.effectAllowed = "move";
  };

  const onDragStartForKind = (
    event: DragEvent<HTMLButtonElement>,
    kind: NodeKind
  ) => {
    event.dataTransfer.setData(
      "application/stai-node-kind",
      JSON.stringify({ kind })
    );
    event.dataTransfer.effectAllowed = "move";
  };

  // addSimpleNode's kind param is narrower than NodeKind (only the six
  // Phase 6 types); every row this is called from is scoped to that set.
  const addSimple = (kind: NodeKind) =>
    addSimpleNode(
      kind as
        | "DATA_CATEGORY"
        | "CONSENT_RECORD"
        | "REGULATORY_REQ"
        | "LEGAL_BASIS"
        | "TRAINING_DATASET"
        | "DEPLOYMENT_ENV",
      nextPosition()
    );

  return (
    <aside className="ai-sidebar">
      <div className="ai-sidebar__title">Organisation</div>
      <button
        type="button"
        className="ai-palette-row"
        draggable
        onDragStart={(e) => onDragStartForKind(e, "DEPARTMENT")}
        onClick={() => addDepartmentNode(nextPosition())}
      >
        <span className="ai-palette-swatch ai-palette-swatch--department" />
        Department
      </button>

      <div className="ai-sidebar__title" style={{ marginTop: 16 }}>
        Actors
      </div>
      {ACTOR_SUBTYPES.map((subtype) => (
        <button
          key={subtype}
          type="button"
          className="ai-palette-row"
          draggable
          onDragStart={(e) => onActorDragStart(e, subtype)}
          onClick={() => addActorNode(nextPosition(), subtype)}
        >
          <span
            className="ai-palette-swatch"
            style={
              subtype === "CONSUMER"
                ? { borderStyle: "dashed", borderColor: "var(--actor-consumer)" }
                : undefined
            }
          />
          {TITLE_CASE[subtype]}
        </button>
      ))}

      <div className="ai-sidebar__title" style={{ marginTop: 16 }}>
        AI System
      </div>
      <button
        type="button"
        className="ai-palette-row"
        draggable
        onDragStart={(e) => onDragStartForKind(e, "AI_MODEL")}
        onClick={() => addAIModelNode(nextPosition())}
      >
        <span className="ai-palette-swatch ai-palette-swatch--ai-model" />
        AI Model
      </button>
      {SIMPLE_ROWS.map((row) => (
        <button
          key={row.kind}
          type="button"
          className="ai-palette-row"
          draggable
          onDragStart={(e) => onDragStartForKind(e, row.kind)}
          onClick={() => addSimple(row.kind)}
        >
          <span className={`ai-palette-swatch ai-palette-swatch--${row.swatch}`} />
          {row.label}
        </button>
      ))}

      <div className="ai-sidebar__title" style={{ marginTop: 16 }}>
        Governance
      </div>
      <button
        type="button"
        className="ai-palette-row"
        draggable
        onDragStart={(e) => onDragStartForKind(e, "CONSTRAINT")}
        onClick={() => addConstraintNode(nextPosition())}
      >
        <span className="ai-palette-swatch ai-palette-swatch--diamond" />
        Constraint
      </button>
      {CONSTRAINT_BUNDLES.map((bundle) => (
        <button
          key={bundle.id}
          type="button"
          className="ai-bundle-row"
          title={bundle.description}
          onClick={() => addConstraintBundle(bundle, nextPosition())}
        >
          <span className="ai-bundle-row__name">{bundle.name}</span>
          <span className="ai-bundle-row__count">
            +{bundle.constraintIds.length}
          </span>
        </button>
      ))}

      <div className="ai-sidebar__title" style={{ marginTop: 16 }}>
        Consent &amp; Regulatory
      </div>
      {CONSENT_ROWS.map((row) => (
        <button
          key={row.kind}
          type="button"
          className="ai-palette-row"
          draggable
          onDragStart={(e) => onDragStartForKind(e, row.kind)}
          onClick={() => addSimple(row.kind)}
        >
          <span className={`ai-palette-swatch ai-palette-swatch--${row.swatch}`} />
          {row.label}
        </button>
      ))}

      <p className="ai-sidebar__note">
        Palette shown for reference. Drag onto the canvas, or click to add.
        Drop an actor inside a department to nest it — its Department field
        updates automatically. Connect nodes to create typed relations
        automatically (e.g. Trainer → AI Model becomes <code>trains</code>).
      </p>
    </aside>
  );
}
