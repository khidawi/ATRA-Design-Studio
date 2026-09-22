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
import type { NodeKind } from "../types";

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
      const kind = event.dataTransfer.getData(
        "application/stai-node-kind"
      ) as NodeKind | "";
      if (!kind || !instanceRef.current) return;

      const position = instanceRef.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      if (kind === "ACTOR") addActorNode(position);
      else if (kind === "CONSTRAINT") addConstraintNode(position);
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
        <Background />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  );
}
