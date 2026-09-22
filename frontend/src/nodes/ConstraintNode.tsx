import { Handle, Position, type NodeProps } from "reactflow";
import { VETO_CONSTRAINT_IDS, type ConstraintNodeData } from "../types";

const statusClass: Record<string, string> = {
  SATISFIED: "ai-node--satisfied",
  UNMET: "ai-node--unmet",
  NOT_YET_DETERMINED: "ai-node--pending",
};

export default function ConstraintNode({
  data,
  selected,
}: NodeProps<ConstraintNodeData>) {
  const isVeto = (VETO_CONSTRAINT_IDS as readonly string[]).includes(
    data.constraintId
  );

  return (
    <div
      className={`ai-node ai-node--constraint ${statusClass[data.status]}${
        selected ? " ai-node--selected" : ""
      }`}
    >
      <Handle type="target" position={Position.Top} />
      <div className="ai-node__kind">
        CONSTRAINT{isVeto ? " · VETO" : ""}
      </div>
      <div className="ai-node__label">{data.constraintId}</div>
      <div className="ai-node__status">{data.status}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
