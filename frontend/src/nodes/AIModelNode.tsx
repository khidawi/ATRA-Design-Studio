import { Handle, Position, type NodeProps } from "reactflow";
import { useRiskRingClass } from "../riskStatus";
import type { AIModelNodeData } from "../types";

const MODEL_TYPE_LABEL: Record<string, string> = {
  LLM: "LLM",
  NN: "Neural Network",
  CNN: "CNN",
  RL: "Reinforcement Learning",
  ENSEMBLE: "Ensemble",
  HYBRID: "Hybrid",
  PINN: "Physics-Informed NN",
};

export default function AIModelNode({
  id,
  data,
  selected,
}: NodeProps<AIModelNodeData>) {
  const riskClass = useRiskRingClass(id);
  return (
    <div className={`ai-model-node${selected ? " ai-model-node--selected" : ""}${riskClass}`}>
      <Handle type="target" position={Position.Top} />
      <div className="ai-model-node__label">
        {data.name || "(unnamed model)"}
      </div>
      <div className="ai-model-node__sub">
        {MODEL_TYPE_LABEL[data.modelType]}
        {data.domain ? ` · ${data.domain}` : ""}
      </div>
      <div className="ai-model-node__tier">{data.aiCriticality}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
