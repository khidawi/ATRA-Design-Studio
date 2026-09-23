import { useEffect } from "react";
import { ReactFlowProvider } from "reactflow";

import Canvas from "./components/Canvas";
import ChatPanel from "./components/ChatPanel";
import Inspector from "./components/Inspector";
import PCSBadge from "./components/PCSBadge";
import Sidebar from "./components/Sidebar";
import ValidationPanel from "./components/ValidationPanel";
import { useCanvasStore } from "./store/useCanvasStore";
import "./App.css";

function App() {
  const loadCatalogue = useCanvasStore((s) => s.loadCatalogue);
  const runScore = useCanvasStore((s) => s.runScore);
  const scoring = useCanvasStore((s) => s.scoring);
  const chatOpen = useCanvasStore((s) => s.chatOpen);
  const toggleChat = useCanvasStore((s) => s.toggleChat);
  const runValidation = useCanvasStore((s) => s.runValidation);
  const validationIssues = useCanvasStore((s) => s.validationIssues);
  const clearCanvas = useCanvasStore((s) => s.clearCanvas);
  const nodeCount = useCanvasStore((s) => s.nodes.length);

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
  }, [loadCatalogue]);

  return (
    <div className="ai-app">
      <header className="ai-header">
        <div className="ai-header__brand">
          <div className="ai-header__mark">S</div>
          <span className="ai-header__title">ST-AI Design Studio</span>
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
            className="ai-score-btn"
            onClick={() => runScore()}
            disabled={scoring}
          >
            {scoring ? "Scoring…" : "Score"}
          </button>
        </div>
      </header>

      <div className="ai-body">
        <Sidebar />
        <ReactFlowProvider>
          <Canvas />
        </ReactFlowProvider>
        <Inspector />
      </div>

      <ChatPanel />
      <ValidationPanel />
    </div>
  );
}

export default App;
