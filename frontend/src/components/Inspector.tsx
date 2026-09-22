import { useCanvasStore } from "../store/useCanvasStore";
import { ACTOR_SUBTYPES, ALL_CONSTRAINT_IDS, CONSTRAINT_STATUSES } from "../types";

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

const STATUS_CLASS: Record<string, string> = {
  NOT_YET_DETERMINED: "ai-status-btn--pending",
  UNMET: "ai-status-btn--unmet",
  SATISFIED: "ai-status-btn--satisfied",
};

export default function Inspector() {
  const nodes = useCanvasStore((s) => s.nodes);
  const selectedNodeId = useCanvasStore((s) => s.selectedNodeId);
  const updateNodeData = useCanvasStore((s) => s.updateNodeData);
  const catalogue = useCanvasStore((s) => s.catalogue);

  const node = nodes.find((n) => n.id === selectedNodeId);

  if (!node) {
    return (
      <aside className="ai-inspector">
        <div className="ai-inspector__title">Properties</div>
        <p className="ai-inspector__empty">
          Click any node on the canvas to inspect and edit its properties.
        </p>
      </aside>
    );
  }

  if (node.data.kind === "ACTOR") {
    const d = node.data;
    return (
      <aside className="ai-inspector">
        <div className="ai-inspector__title">Properties</div>
        <div className="ai-inspector__kicker ai-inspector__kicker--actor">
          Actor · {TITLE_CASE[d.subtype]}
        </div>
        <div className="ai-inspector__heading">{TITLE_CASE[d.subtype]}</div>

        <label className="ai-field">
          <span>Subtype</span>
          <select
            value={d.subtype}
            onChange={(e) =>
              updateNodeData(node.id, {
                subtype: e.target.value as typeof d.subtype,
              })
            }
          >
            {ACTOR_SUBTYPES.map((s) => (
              <option key={s} value={s}>
                {TITLE_CASE[s]}
              </option>
            ))}
          </select>
        </label>

        <label className="ai-field">
          <span>Identity</span>
          <input
            type="text"
            value={d.identity}
            placeholder="e.g. Data Science ML Team"
            onChange={(e) =>
              updateNodeData(node.id, { identity: e.target.value })
            }
          />
        </label>

        <div className="ai-inspector__footnote">
          Actor nodes show identity and department. Connect an actor to a
          constraint to create an <code>on_dependency</code> edge.
        </div>
      </aside>
    );
  }

  const d = node.data;
  const meta = catalogue.find((c) => c.constraint_id === d.constraintId);
  const needsEvidence = d.status === "SATISFIED";

  return (
    <aside className="ai-inspector">
      <div className="ai-inspector__title">Properties</div>
      <div className="ai-inspector__kicker ai-inspector__kicker--constraint">
        Security Constraint
      </div>
      <div className="ai-inspector__heading">{d.constraintId}</div>

      <label className="ai-field">
        <span>Constraint ID</span>
        <select
          value={d.constraintId}
          onChange={(e) =>
            updateNodeData(node.id, { constraintId: e.target.value })
          }
        >
          {ALL_CONSTRAINT_IDS.map((cid) => (
            <option key={cid} value={cid}>
              {cid}
            </option>
          ))}
        </select>
      </label>

      {meta && (
        <p className="ai-field__meta">
          <strong>{meta.class === "veto" ? "Veto class" : "Modulating"}</strong>
          {meta.name ? ` — ${meta.name}` : ""}
        </p>
      )}

      <div className="ai-field">
        <span>Status</span>
        <div className="ai-status-row">
          {CONSTRAINT_STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              className={`ai-status-btn ${STATUS_CLASS[s]}${
                d.status === s ? " ai-status-btn--active" : ""
              }`}
              onClick={() => updateNodeData(node.id, { status: s })}
            >
              {STATUS_LABEL[s]}
            </button>
          ))}
        </div>
      </div>

      <label className="ai-field">
        <span>
          Evidence
          {needsEvidence ? " (required to mark Satisfied)" : ""}
        </span>
        <textarea
          rows={4}
          value={d.evidence}
          placeholder={
            needsEvidence
              ? "Required — SATISFIED status is rejected server-side without evidence"
              : "Optional"
          }
          onChange={(e) =>
            updateNodeData(node.id, { evidence: e.target.value })
          }
        />
      </label>

      <div className="ai-inspector__footnote">
        Veto-class constraints can only reach Satisfied with non-empty
        evidence — enforced server-side on every <code>/score</code> call.
      </div>
    </aside>
  );
}
