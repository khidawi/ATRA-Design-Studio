import { useRef, useState } from "react";
import { useCanvasStore } from "../store/useCanvasStore";

const SAMPLE = `{
  "deployment_name": "Clinical Triage LLM",
  "assessment_domain": "HEALTHCARE",
  "departments": [{ "temp_id": "dept-ds", "name": "Data Science" }],
  "actors": [
    { "temp_id": "a1", "subtype": "TRAINER", "identity": "Data Science Team", "department_temp_id": "dept-ds" }
  ],
  "ai_models": [
    { "temp_id": "m1", "name": "GPT-4 Triage Assistant", "model_type": "LLM", "ai_criticality": "CRITICAL" }
  ],
  "deployment_environments": [
    { "temp_id": "e1", "name": "Production", "description": "Hospital network, 10k staff" }
  ]
}`;

export default function ImportPanel() {
  const importOpen = useCanvasStore((s) => s.importOpen);
  const importLoading = useCanvasStore((s) => s.importLoading);
  const importError = useCanvasStore((s) => s.importError);
  const closeImport = useCanvasStore((s) => s.closeImport);
  const importDeploymentJson = useCanvasStore((s) => s.importDeploymentJson);
  const [text, setText] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!importOpen) return null;

  const submit = async () => {
    if (!text.trim() || importLoading) return;
    const ok = await importDeploymentJson(text);
    if (ok) setText("");
  };

  const onFilePicked = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-picking the same file later
    if (!file) return;
    const content = await file.text();
    setText(content);
  };

  return (
    <div className="ai-import-panel">
      <div className="ai-import-panel__header">
        <span>Import deployment JSON</span>
        <button type="button" className="ai-import-panel__close" onClick={closeImport}>
          ×
        </button>
      </div>

      <div className="ai-import-panel__body">
        <p className="ai-import-panel__hint">
          Upload or paste a deployment description to auto-populate the
          canvas with its departments, actors, AI model, and deployment
          environment. Compliance fields (DPIA, HITL, etc.) always land as
          Not Yet Determined — a JSON file can't mark them satisfied.
        </p>

        <div className="ai-import-panel__file-row">
          <button
            type="button"
            className="ai-import-panel__file-btn"
            onClick={() => fileInputRef.current?.click()}
          >
            Choose file…
          </button>
          <button
            type="button"
            className="ai-import-panel__file-btn"
            onClick={() => setText(SAMPLE)}
          >
            Use sample
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept="application/json,.json"
            onChange={onFilePicked}
            style={{ display: "none" }}
          />
        </div>

        <textarea
          className="ai-import-panel__textarea"
          rows={10}
          value={text}
          placeholder="Paste deployment-description JSON here, or choose a file above…"
          onChange={(e) => setText(e.target.value)}
        />

        {importError && <div className="ai-import-panel__error">{importError}</div>}
      </div>

      <div className="ai-import-panel__footer">
        <button type="button" onClick={closeImport} className="ai-import-panel__cancel">
          Cancel
        </button>
        <button
          type="button"
          onClick={submit}
          disabled={importLoading || !text.trim()}
          className="ai-import-panel__submit"
        >
          {importLoading ? "Importing…" : "Import"}
        </button>
      </div>
    </div>
  );
}
