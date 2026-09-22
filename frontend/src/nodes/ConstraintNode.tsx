import { Handle, Position, type NodeProps } from "reactflow";
import type { ConstraintNodeData } from "../types";

const statusClass: Record<ConstraintNodeData["status"], string> = {
  SATISFIED: "ai-constraint-node--satisfied",
  UNMET: "ai-constraint-node--unmet",
  NOT_YET_DETERMINED: "",
};

export default function ConstraintNode({
  data,
  selected,
}: NodeProps<ConstraintNodeData>) {
  const shortLabel = data.constraintId.replace(/^SC-|-\d+$/g, "");

  return (
    <div
      className={`ai-constraint-node ${statusClass[data.status]}${
        selected ? " ai-constraint-node--selected" : ""
      }`}
    >
      <Handle type="target" position={Position.Top} />
      <div className="ai-constraint-node__diamond">
        <span className="ai-constraint-node__label">{shortLabel}</span>
      </div>
      <div className="ai-constraint-node__caption">{data.constraintId}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
