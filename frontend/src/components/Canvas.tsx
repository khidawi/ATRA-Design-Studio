import { useCallback, useMemo, useRef } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type ReactFlowInstance,
} from "reactflow";
import "reactflow/dist/style.css";

import AIModelNode from "../nodes/AIModelNode";
import ActorNode from "../nodes/ActorNode";
import ConstraintNode from "../nodes/ConstraintNode";
import DepartmentNode from "../nodes/DepartmentNode";
import { useCanvasStore } from "../store/useCanvasStore";
import type { ActorSubtype, NodeKind } from "../types";

const nodeTypes = {
  actorNode: ActorNode,
  constraintNode: ConstraintNode,
  departmentNode: DepartmentNode,
  aiModelNode: AIModelNode,
};

export default function Canvas() {
  const nodes = useCanvasStore((s) => s.nodes);
  const edges = useCanvasStore((s) => s.edges);
  const onNodesChange = useCanvasStore((s) => s.onNodesChange);
  const onEdgesChange = useCanvasStore((s) => s.onEdgesChange);
  const onConnect = useCanvasStore((s) => s.onConnect);
  const addActorNode = useCanvasStore((s) => s.addActorNode);
  const addConstraintNode = useCanvasStore((s) => s.addConstraintNode);
  const addDepartmentNode = useCanvasStore((s) => s.addDepartmentNode);
  const addAIModelNode = useCanvasStore((s) => s.addAIModelNode);
  const setSelectedNode = useCanvasStore((s) => s.setSelectedNode);
  const settleNodeParent = useCanvasStore((s) => s.settleNodeParent);

  const wrapperRef = useRef<HTMLDivElement>(null);
  const instanceRef = useRef<ReactFlowInstance | null>(null);

  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
  }, []);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();
      const raw = event.dataTransfer.getData("application/stai-node-kind");
      if (!raw || !instanceRef.current) return;

      const payload = JSON.parse(raw) as {
        kind: NodeKind;
        subtype?: ActorSubtype;
      };

      const position = instanceRef.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      if (payload.kind === "ACTOR") {
        addActorNode(position, payload.subtype);
        const newId = useCanvasStore.getState().selectedNodeId;
        if (newId) settleNodeParent(newId);
      } else if (payload.kind === "CONSTRAINT") {
        addConstraintNode(position);
      } else if (payload.kind === "DEPARTMENT") {
        addDepartmentNode(position);
      } else if (payload.kind === "AI_MODEL") {
        addAIModelNode(position);
      }
    },
    [
      addActorNode,
      addConstraintNode,
      addDepartmentNode,
      addAIModelNode,
      settleNodeParent,
    ]
  );

  const onPaneClick = useCallback(
    () => setSelectedNode(null),
    [setSelectedNode]
  );

  const onNodeClick = useCallback(
    (_: unknown, node: { id: string }) => setSelectedNode(node.id),
    [setSelectedNode]
  );

  const nodeTypesMemo = useMemo(() => nodeTypes, []);

  return (
    <div className="ai-canvas" ref={wrapperRef}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypesMemo}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        onInit={(instance) => (instanceRef.current = instance)}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onPaneClick={onPaneClick}
        onNodeClick={onNodeClick}
        fitView
      >
        <Background gap={22} size={1.5} color="#1e293b" />
        <Controls />
        <MiniMap
          maskColor="rgba(11, 18, 32, 0.7)"
          nodeColor="#334155"
          nodeStrokeWidth={0}
        />
      </ReactFlow>
    </div>
  );
}
