import type { DragEvent } from "react";
import { useCanvasStore } from "../store/useCanvasStore";
import type { NodeKind } from "../types";

const onDragStart = (event: DragEvent<HTMLDivElement>, kind: NodeKind) => {
  event.dataTransfer.setData("application/stai-node-kind", kind);
  event.dataTransfer.effectAllowed = "move";
};

export default function Sidebar() {
  const nodes = useCanvasStore((s) => s.nodes);
  const addActorNode = useCanvasStore((s) => s.addActorNode);
  const addConstraintNode = useCanvasStore((s) => s.addConstraintNode);

  const nextPosition = () => {
    const i = nodes.length;
    return { x: 80 + (i % 4) * 190, y: 60 + Math.floor(i / 4) * 130 };
  };

  return (
    <aside className="ai-sidebar">
      <h2 className="ai-sidebar__title">Palette</h2>
      <p className="ai-sidebar__hint">Drag onto the canvas, or click to add</p>

      <div
        className="ai-palette-item ai-palette-item--actor"
        draggable
        onDragStart={(e) => onDragStart(e, "ACTOR")}
        onClick={() => addActorNode(nextPosition())}
      >
        Actor
      </div>

      <div
        className="ai-palette-item ai-palette-item--constraint"
        draggable
        onDragStart={(e) => onDragStart(e, "CONSTRAINT")}
        onClick={() => addConstraintNode(nextPosition())}
      >
        Constraint
      </div>

      <p className="ai-sidebar__note">
        Connect nodes to create an <code>on_dependency</code> edge. More node
        types (Department, AI Model, Dataset, …) land in a later pass.
      </p>
    </aside>
  );
}
