import { useEffect } from "react";
import { ReactFlowProvider } from "reactflow";

import Canvas from "./components/Canvas";
import Inspector from "./components/Inspector";
import PCSBadge from "./components/PCSBadge";
import Sidebar from "./components/Sidebar";
import { useCanvasStore } from "./store/useCanvasStore";
import "./App.css";

function App() {
  const loadCatalogue = useCanvasStore((s) => s.loadCatalogue);
  const runScore = useCanvasStore((s) => s.runScore);
  const scoring = useCanvasStore((s) => s.scoring);

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
    </div>
  );
}

export default App;
