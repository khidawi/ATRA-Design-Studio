import { Handle, Position, type NodeProps } from "reactflow";
import { useRiskRingClass } from "../riskStatus";
import type { ActorNodeData } from "../types";

const TITLE_CASE: Record<ActorNodeData["subtype"], string> = {
  TRAINER: "Trainer",
  VALIDATOR: "Validator",
  DEPLOYER: "Deployer",
  OPERATOR: "Operator",
  CONSUMER: "Consumer",
};

export default function ActorNode({ id, data, selected }: NodeProps<ActorNodeData>) {
  const isConsumer = data.subtype === "CONSUMER";
  const riskClass = useRiskRingClass(id);
  return (
    <div
      className={`ai-actor-node${isConsumer ? " ai-actor-node--consumer" : ""}${
        selected ? " ai-actor-node--selected" : ""
      }${riskClass}`}
    >
      <Handle type="target" position={Position.Top} />
      <div className="ai-actor-node__label">{TITLE_CASE[data.subtype]}</div>
      <div className="ai-actor-node__sub">{data.identity || "(unnamed)"}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
