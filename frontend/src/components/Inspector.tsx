import { useCanvasStore } from "../store/useCanvasStore";
import { ACTOR_SUBTYPES, ALL_CONSTRAINT_IDS, CONSTRAINT_STATUSES } from "../types";

export default function Inspector() {
  const nodes = useCanvasStore((s) => s.nodes);
  const selectedNodeId = useCanvasStore((s) => s.selectedNodeId);
  const updateNodeData = useCanvasStore((s) => s.updateNodeData);
  const catalogue = useCanvasStore((s) => s.catalogue);

  const node = nodes.find((n) => n.id === selectedNodeId);

  if (!node) {
    return (
      <aside className="ai-inspector">
        <h2 className="ai-inspector__title">Inspector</h2>
        <p className="ai-inspector__hint">Select a node to edit it.</p>
      </aside>
    );
  }

  if (node.data.kind === "ACTOR") {
    const d = node.data;
    return (
      <aside className="ai-inspector">
        <h2 className="ai-inspector__title">Actor</h2>

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
                {s}
              </option>
            ))}
          </select>
        </label>

        <label className="ai-field">
          <span>Identity</span>
          <input
            type="text"
            value={d.identity}
            placeholder="e.g. acme-ml-team"
            onChange={(e) =>
              updateNodeData(node.id, { identity: e.target.value })
            }
          />
        </label>
      </aside>
    );
  }

  const d = node.data;
  const meta = catalogue.find((c) => c.constraint_id === d.constraintId);
  const needsEvidence = d.status === "SATISFIED";

  return (
    <aside className="ai-inspector">
      <h2 className="ai-inspector__title">Constraint</h2>

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

      <label className="ai-field">
        <span>Status</span>
        <select
          value={d.status}
          onChange={(e) =>
            updateNodeData(node.id, {
              status: e.target.value as typeof d.status,
            })
          }
        >
          {CONSTRAINT_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </label>

      <label className="ai-field">
        <span>
          Evidence
          {needsEvidence ? " (required)" : ""}
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
    </aside>
  );
}
