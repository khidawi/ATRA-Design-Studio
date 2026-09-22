import { NodeResizer } from "@reactflow/node-resizer";
import "@reactflow/node-resizer/dist/style.css";
import type { NodeProps } from "reactflow";
import type { DepartmentNodeData } from "../types";

export default function DepartmentNode({
  data,
  selected,
}: NodeProps<DepartmentNodeData>) {
  return (
    <div className="ai-department-node">
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
