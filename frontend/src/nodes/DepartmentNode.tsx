import { NodeResizer } from "@reactflow/node-resizer";
import "@reactflow/node-resizer/dist/style.css";
import type { NodeProps } from "reactflow";
import { useRiskRingClass } from "../riskStatus";
import type { DepartmentNodeData } from "../types";

export default function DepartmentNode({
  id,
  data,
  selected,
}: NodeProps<DepartmentNodeData>) {
  const riskClass = useRiskRingClass(id);
  return (
    <div className={`ai-department-node${riskClass}`}>
      <NodeResizer
        isVisible={selected}
        minWidth={200}
        minHeight={140}
        color="#3b82f6"
      />
      <div className="ai-department-node__pill">
        {data.name || "Department"}
      </div>
    </div>
  );
}
