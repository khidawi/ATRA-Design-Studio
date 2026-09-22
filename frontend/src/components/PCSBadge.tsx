import { useCanvasStore } from "../store/useCanvasStore";

const gateClass: Record<string, string> = {
  APPROVED: "ai-badge--approved",
  REVIEW: "ai-badge--review",
  BLOCKED: "ai-badge--blocked",
};

export default function PCSBadge() {
  const scoreResult = useCanvasStore((s) => s.scoreResult);
  const scoreWarnings = useCanvasStore((s) => s.scoreWarnings);
  const scoring = useCanvasStore((s) => s.scoring);
  const scoreError = useCanvasStore((s) => s.scoreError);

  if (scoring) {
    return <div className="ai-badge ai-badge--pending">Scoring…</div>;
  }

  if (scoreError) {
    return (
      <div className="ai-badge ai-badge--error" title={scoreError}>
        422 Rejected: {scoreError}
      </div>
    );
  }

  if (!scoreResult) {
    return <div className="ai-badge ai-badge--idle">Not scored yet</div>;
  }

  const gate = scoreResult.gate ?? "UNKNOWN";

  return (
    <div className="ai-badge-group">
      <div className={`ai-badge ${gateClass[gate] ?? ""}`}>
        {gate} · {scoreResult.tier ?? "?"} · PCS{" "}
        {scoreResult.pcs_final?.toFixed(2) ?? "—"}
      </div>
      {scoreResult.unmet_veto_constraints.length > 0 && (
        <div className="ai-badge__veto-list">
          Unmet veto constraints: {scoreResult.unmet_veto_constraints.join(", ")}
        </div>
      )}
      {scoreWarnings.length > 0 && (
        <div className="ai-badge__warnings">{scoreWarnings.join(" · ")}</div>
      )}
    </div>
  );
}
