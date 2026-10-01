import { useEffect } from "react";
import { ReactFlowProvider } from "reactflow";

import Canvas from "./components/Canvas";
import ChatPanel from "./components/ChatPanel";
import ImportPanel from "./components/ImportPanel";
import Inspector from "./components/Inspector";
import PCSBadge from "./components/PCSBadge";
import RiskPanel from "./components/RiskPanel";
import Sidebar from "./components/Sidebar";
import ValidationPanel from "./components/ValidationPanel";
import { useCanvasStore } from "./store/useCanvasStore";
import "./App.css";

function App() {
  const loadCatalogue = useCanvasStore((s) => s.loadCatalogue);
  const loadDomains = useCanvasStore((s) => s.loadDomains);
  const domains = useCanvasStore((s) => s.domains);
  const selectedDomain = useCanvasStore((s) => s.selectedDomain);
  const setSelectedDomain = useCanvasStore((s) => s.setSelectedDomain);
  const runScore = useCanvasStore((s) => s.runScore);
  const scoring = useCanvasStore((s) => s.scoring);
  const chatOpen = useCanvasStore((s) => s.chatOpen);
  const toggleChat = useCanvasStore((s) => s.toggleChat);
  const importOpen = useCanvasStore((s) => s.importOpen);
  const toggleImport = useCanvasStore((s) => s.toggleImport);
  const runValidation = useCanvasStore((s) => s.runValidation);
  const validationIssues = useCanvasStore((s) => s.validationIssues);
  const clearCanvas = useCanvasStore((s) => s.clearCanvas);
  const nodes = useCanvasStore((s) => s.nodes);
  const edges = useCanvasStore((s) => s.edges);
  const nodeCount = nodes.length;
  const riskOpen = useCanvasStore((s) => s.riskOpen);
  const toggleRisk = useCanvasStore((s) => s.toggleRisk);
  const riskAssessment = useCanvasStore((s) => s.riskAssessment);
  const runAssessment = useCanvasStore((s) => s.runAssessment);

  const onClearCanvas = () => {
    if (nodeCount === 0) return;
    if (
      window.confirm(
        "Clear the canvas? This removes every node and edge — your browser won't have it anymore."
      )
    ) {
      clearCanvas();
    }
  };

  useEffect(() => {
    loadCatalogue();
    loadDomains();
  }, [loadCatalogue, loadDomains]);

  // Task 1.4: node colours and the Risk Assessment panel stay live on
  // every graph/domain change, debounced so a drag or a burst of edits
  // doesn't fire a request per intermediate frame.
  useEffect(() => {
    const t = setTimeout(() => {
      runAssessment();
    }, 500);
    return () => clearTimeout(t);
  }, [nodes, edges, selectedDomain, runAssessment]);

  return (
    <div className="ai-app">
      <header className="ai-header">
        <div className="ai-header__brand">
          <div className="ai-header__mark">S</div>
          <span className="ai-header__title">ST-AI Design Studio</span>
        </div>
        <div className="ai-header__domain">
          <label htmlFor="ai-domain-select" className="ai-header__domain-label">
            Assessment Domain
          </label>
          <select
            id="ai-domain-select"
            className="ai-domain-select"
            value={selectedDomain}
            onChange={(e) => setSelectedDomain(e.target.value)}
            disabled={domains.length === 0}
          >
            {domains.length === 0 && <option value={selectedDomain}>{selectedDomain}</option>}
            {domains.map((d) => (
              <option key={d.domain_id} value={d.domain_id}>
                {d.name}
              </option>
            ))}
          </select>
        </div>
        <div className="ai-header__spacer" />
        <div className="ai-header__actions">
          <PCSBadge />
          <button
            type="button"
            className="ai-clear-btn"
            onClick={onClearCanvas}
            disabled={nodeCount === 0}
            title="Clear the canvas and its saved copy in this browser"
          >
            New
          </button>
          <button
            type="button"
            className={`ai-chat-toggle${importOpen ? " ai-chat-toggle--active" : ""}`}
            onClick={toggleImport}
            title="Import a deployment description JSON to auto-populate the canvas"
          >
            Import JSON
          </button>
          <button
            type="button"
            className={`ai-chat-toggle${chatOpen ? " ai-chat-toggle--active" : ""}`}
            onClick={toggleChat}
          >
            Chat
          </button>
          <button
            type="button"
            className="ai-validate-toggle"
            onClick={runValidation}
          >
            Validate
            {validationIssues.length > 0 && (
              <span className="ai-validate-toggle__badge">
                {validationIssues.length}
              </span>
            )}
          </button>
          <button
            type="button"
            className={`ai-validate-toggle${riskOpen ? " ai-chat-toggle--active" : ""}`}
            onClick={toggleRisk}
            title="Risk Assessment: per-regulation breakdown against the selected domain"
          >
            Risk
            {riskAssessment && riskAssessment.overall_status !== "GREEN" && (
              <span
                className={`ai-validate-toggle__badge${
                  riskAssessment.overall_status === "AMBER" ? " ai-validate-toggle__badge--amber" : ""
                }`}
              >
                {riskAssessment.element_verdicts.filter((v) => v.status !== "GREEN").length}
              </span>
            )}
          </button>
          <button
            type="button"
            className="ai-score-btn"
            onClick={() => runScore()}
            disabled={scoring}
          >
            {scoring ? "Scoring…" : "Score"}
          </button>
        </div>
      </header>

      <div className={`ai-body${riskOpen ? " ai-body--risk-open" : ""}`}>
        <Sidebar />
        <ReactFlowProvider>
          <Canvas />
        </ReactFlowProvider>
        <Inspector />
        <RiskPanel />
      </div>

      <ChatPanel />
      <ImportPanel />
      <ValidationPanel />
    </div>
  );
}

export default App;
