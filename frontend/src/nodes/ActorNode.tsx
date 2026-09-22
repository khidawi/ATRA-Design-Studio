import { Handle, Position, type NodeProps } from "reactflow";
import type { ActorNodeData } from "../types";

export default function ActorNode({ data, selected }: NodeProps<ActorNodeData>) {
  return (
    <div className={`ai-node ai-node--actor${selected ? " ai-node--selected" : ""}`}>
      <Handle type="target" position={Position.Top} />
      <div className="ai-node__kind">ACTOR · {data.subtype}</div>
      <div className="ai-node__label">{data.identity || "(unnamed)"}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
