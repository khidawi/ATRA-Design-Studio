import { useCanvasStore } from "../store/useCanvasStore";

function downloadContract(contract: object, filename: string) {
  const blob = new Blob([JSON.stringify(contract, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function RiskPanel() {
  const riskOpen = useCanvasStore((s) => s.riskOpen);
  const riskAssessment = useCanvasStore((s) => s.riskAssessment);
  const riskLoading = useCanvasStore((s) => s.riskLoading);
  const riskError = useCanvasStore((s) => s.riskError);
  const closeRisk = useCanvasStore((s) => s.closeRisk);
  const setSelectedNode = useCanvasStore((s) => s.setSelectedNode);
  const nodes = useCanvasStore((s) => s.nodes);
  const compiling = useCanvasStore((s) => s.compiling);
  const compileError = useCanvasStore((s) => s.compileError);
  const compiledContract = useCanvasStore((s) => s.compiledContract);
  const compileDesign = useCanvasStore((s) => s.compileDesign);

  if (!riskOpen) return null;

  const isGreen = riskAssessment?.overall_status === "GREEN";

  const nodeIds = new Set(nodes.map((n) => n.id));
  const flagged = (riskAssessment?.element_verdicts ?? []).filter(
    (v) => v.status !== "GREEN"
  );

  return (
    <div className="ai-risk-panel">
      <div className="ai-risk-panel__header">
        <span>Risk Assessment{riskLoading ? " — updating…" : ""}</span>
        <button type="button" className="ai-risk-panel__close" onClick={closeRisk} aria-label="Close">
          ×
        </button>
      </div>

      <div className="ai-risk-panel__body">
        {riskError && <div className="ai-risk-panel__error">{riskError}</div>}

        {!riskAssessment && !riskError && (
          <p className="ai-risk-panel__empty">Assessing the current design…</p>
        )}

        {riskAssessment && (
          <>
            <div
              className={`ai-risk-overall ai-risk-overall--${riskAssessment.overall_status.toLowerCase()}`}
            >
              <span className="ai-risk-overall__dot" />
              Overall: {riskAssessment.overall_status}
            </div>

            <div className="ai-compile-section">
              <button
                type="button"
                className="ai-compile-btn"
                onClick={() => compileDesign()}
                disabled={!isGreen || compiling}
                title={
                  isGreen
                    ? "Compile this all-green design to a signed contract file"
                    : "Every element must be green before this design can compile"
                }
              >
                {compiling ? "Compiling…" : "Compile Contract"}
              </button>

              {compileError && <div className="ai-risk-panel__error">{compileError}</div>}

              {compiledContract && (
                <div className="ai-compile-result">
                  <div className="ai-compile-result__row">
                    <span>Version</span>
                    <span>{compiledContract.version}</span>
                  </div>
                  <div className="ai-compile-result__row">
                    <span>Status</span>
                    <span>{compiledContract.status}</span>
                  </div>
                  <div className="ai-compile-result__row ai-compile-result__row--hash">
                    <span>Hash</span>
                    <code title={compiledContract.contract_hash}>
                      {compiledContract.contract_hash.slice(0, 16)}…
                    </code>
                  </div>
                  <button
                    type="button"
                    className="ai-compile-download-btn"
                    onClick={() =>
                      downloadContract(
                        compiledContract,
                        `contract-${compiledContract.contract_id}.json`
                      )
                    }
                  >
                    Download contract file
                  </button>
                </div>
              )}
            </div>

            <div className="ai-risk-breakdown">
              {riskAssessment.score_breakdown.map((b) => (
                <div
                  key={b.category}
                  className={`ai-risk-breakdown-row ai-risk-breakdown-row--${b.status.toLowerCase()}`}
                >
                  <span className="ai-risk-breakdown-row__name">{b.category}</span>
                  <span className="ai-risk-breakdown-row__counts">
                    {b.passed} pass · {b.failed} fail · {b.unknown} unknown
                  </span>
                </div>
              ))}
            </div>

            <div className="ai-risk-panel__list-title">
              Flagged elements {flagged.length > 0 ? `(${flagged.length})` : ""}
            </div>
            <div className="ai-risk-panel__list">
              {flagged.length === 0 && (
                <p className="ai-risk-panel__empty">
                  No flagged elements — every rule in this domain passes.
                </p>
              )}
              {flagged.map((v, i) => {
                const hasNode = nodeIds.has(v.node_id);
                return (
                  <button
                    key={i}
                    type="button"
                    className={`ai-risk-issue ai-risk-issue--${v.status.toLowerCase()}`}
                    onClick={() => hasNode && setSelectedNode(v.node_id)}
                    disabled={!hasNode}
                    title={hasNode ? "Click to select this element" : "No canvas element to select"}
                  >
                    <span className="ai-risk-issue__citation">
                      {v.citation ?? "No citation"}
                    </span>
                    <span className="ai-risk-issue__reason">{v.reason}</span>
                  </button>
                );
              })}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
