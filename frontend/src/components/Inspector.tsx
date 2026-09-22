import type { FieldDescriptor, RenderCtx } from "../nodeSchema";
import { NODE_SCHEMA } from "../nodeSchema";
import { useCanvasStore } from "../store/useCanvasStore";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function Field({
  field,
  data,
  nodeId,
  ctx,
  onChange,
}: {
  field: FieldDescriptor<any>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any;
  nodeId: string;
  ctx: RenderCtx;
  onChange: (patch: Record<string, string>) => void;
}) {
  const value = data[field.key] ?? "";

  if (field.kind === "dynamic-select") {
    const options = field.dynamicOptions(ctx, nodeId);
    return (
      <label className="ai-field">
        <span>{field.label}</span>
        <select
          value={value}
          onChange={(e) => onChange({ [field.key]: e.target.value })}
        >
          <option value="">{field.emptyLabel}</option>
          {options.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (field.kind === "select") {
    return (
      <label className="ai-field">
        <span>{field.label}</span>
        <select
          value={value}
          onChange={(e) => onChange({ [field.key]: e.target.value })}
        >
          {field.options.map((opt) => (
            <option key={opt} value={opt}>
              {field.optionLabels?.[opt] ?? opt}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (field.kind === "text") {
    return (
      <label className="ai-field">
        <span>{field.label}</span>
        <input
          type="text"
          value={value}
          placeholder={field.placeholder}
          onChange={(e) => onChange({ [field.key]: e.target.value })}
        />
      </label>
    );
  }

  if (field.kind === "textarea") {
    const helper = field.helper?.(data);
    return (
      <label className="ai-field">
        <span>
          {field.label}
          {helper ? ` ${helper}` : ""}
        </span>
        <textarea
          rows={4}
          value={value}
          placeholder={field.placeholder?.(data)}
          onChange={(e) => onChange({ [field.key]: e.target.value })}
        />
      </label>
    );
  }

  // status-buttons
  return (
    <div className="ai-field">
      <span>{field.label}</span>
      <div className="ai-status-row">
        {field.options.map((opt) => (
          <button
            key={opt}
            type="button"
            className={`ai-status-btn ai-status-btn--${field.variant[opt]}${
              value === opt ? " ai-status-btn--active" : ""
            }`}
            onClick={() => onChange({ [field.key]: opt })}
          >
            {field.optionLabels[opt]}
          </button>
        ))}
      </div>
    </div>
  );
}

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

  const descriptor = NODE_SCHEMA[node.data.kind];

  if (!descriptor) {
    return (
      <aside className="ai-inspector">
        <div className="ai-inspector__title">Properties</div>
        <p className="ai-inspector__empty">
          No editor is defined yet for this node type.
        </p>
      </aside>
    );
  }

  const departments = nodes
    .filter(
      (n): n is typeof n & { data: { kind: "DEPARTMENT"; name: string } } =>
        n.data.kind === "DEPARTMENT"
    )
    .map((n) => ({ id: n.id, name: n.data.name || "(unnamed department)" }));

  const ctx: RenderCtx = { catalogue, departments };

  return (
    <aside className="ai-inspector">
      <div className="ai-inspector__title">Properties</div>
      <div
        className={`ai-inspector__kicker ai-inspector__kicker--${descriptor.kickerClass}`}
      >
        {descriptor.kicker(node.data)}
      </div>
      <div className="ai-inspector__heading">
        {descriptor.heading(node.data)}
      </div>

      {descriptor.renderMeta?.(node.data, ctx)}

      {descriptor.fields.map((field) => (
        <Field
          key={field.key}
          field={field}
          data={node.data}
          nodeId={node.id}
          ctx={ctx}
          onChange={(patch) => updateNodeData(node.id, patch)}
        />
      ))}

      <div className="ai-inspector__footnote">{descriptor.footnote}</div>
    </aside>
  );
}
