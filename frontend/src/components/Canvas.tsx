import { useCallback, useMemo, useRef } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  type ReactFlowInstance,
} from "reactflow";
import "reactflow/dist/style.css";

import ActorNode from "../nodes/ActorNode";
import ConstraintNode from "../nodes/ConstraintNode";
import { useCanvasStore } from "../store/useCanvasStore";
import type { ActorSubtype, NodeKind } from "../types";

const nodeTypes = { actorNode: ActorNode, constraintNode: ConstraintNode };

export default function Canvas() {
  const nodes = useCanvasStore((s) => s.nodes);
  const edges = useCanvasStore((s) => s.edges);
  const onNodesChange = useCanvasStore((s) => s.onNodesChange);
  const onEdgesChange = useCanvasStore((s) => s.onEdgesChange);
  const onConnect = useCanvasStore((s) => s.onConnect);
  const addActorNode = useCanvasStore((s) => s.addActorNode);
  const addConstraintNode = useCanvasStore((s) => s.addConstraintNode);
  const setSelectedNode = useCanvasStore((s) => s.setSelectedNode);

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

      if (payload.kind === "ACTOR") addActorNode(position, payload.subtype);
      else if (payload.kind === "CONSTRAINT") addConstraintNode(position);
    },
    [addActorNode, addConstraintNode]
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
