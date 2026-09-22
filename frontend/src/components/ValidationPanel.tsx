import { useCanvasStore } from "../store/useCanvasStore";

export default function ValidationPanel() {
  const validationOpen = useCanvasStore((s) => s.validationOpen);
  const validationIssues = useCanvasStore((s) => s.validationIssues);
  const closeValidation = useCanvasStore((s) => s.closeValidation);
  const setSelectedNode = useCanvasStore((s) => s.setSelectedNode);

  if (!validationOpen) return null;

  const errors = validationIssues.filter((i) => i.severity === "error");
  const warnings = validationIssues.filter((i) => i.severity === "warning");

  return (
    <div className="ai-validation-panel">
      <div className="ai-validation-panel__header">
        <span>
          Validation
          {validationIssues.length > 0
            ? ` — ${errors.length} error${errors.length === 1 ? "" : "s"}, ${warnings.length} warning${warnings.length === 1 ? "" : "s"}`
            : ""}
        </span>
        <button type="button" onClick={closeValidation} aria-label="Close">
          ×
        </button>
      </div>
      <div className="ai-validation-panel__list">
        {validationIssues.length === 0 && (
          <p className="ai-validation-panel__empty">
            No structural issues found — every node is connected, no
            duplicate role fillers, no unsupported evidence gaps.
          </p>
        )}
        {validationIssues.map((issue, i) => (
          <button
            key={i}
            type="button"
            className={`ai-validation-issue ai-validation-issue--${issue.severity}`}
            onClick={() => issue.nodeId && setSelectedNode(issue.nodeId)}
            disabled={!issue.nodeId}
          >
            {issue.message}
          </button>
        ))}
      </div>
    </div>
  );
}
