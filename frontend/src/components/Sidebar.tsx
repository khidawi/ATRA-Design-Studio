import type { DragEvent } from "react";
import { useCanvasStore } from "../store/useCanvasStore";
import { ACTOR_SUBTYPES, type ActorSubtype } from "../types";

const TITLE_CASE: Record<ActorSubtype, string> = {
  TRAINER: "Trainer",
  VALIDATOR: "Validator",
  DEPLOYER: "Deployer",
  OPERATOR: "Operator",
  CONSUMER: "Consumer",
};

export default function Sidebar() {
  const nodes = useCanvasStore((s) => s.nodes);
  const addActorNode = useCanvasStore((s) => s.addActorNode);
  const addConstraintNode = useCanvasStore((s) => s.addConstraintNode);

  const nextPosition = () => {
    const i = nodes.length;
    return { x: 80 + (i % 4) * 190, y: 60 + Math.floor(i / 4) * 130 };
  };

  const onActorDragStart = (
    event: DragEvent<HTMLButtonElement>,
    subtype: ActorSubtype
  ) => {
    event.dataTransfer.setData(
      "application/stai-node-kind",
      JSON.stringify({ kind: "ACTOR", subtype })
    );
    event.dataTransfer.effectAllowed = "move";
  };

  const onConstraintDragStart = (event: DragEvent<HTMLButtonElement>) => {
    event.dataTransfer.setData(
      "application/stai-node-kind",
      JSON.stringify({ kind: "CONSTRAINT" })
    );
    event.dataTransfer.effectAllowed = "move";
  };

  return (
    <aside className="ai-sidebar">
      <div className="ai-sidebar__title">Actors</div>
      {ACTOR_SUBTYPES.map((subtype) => (
        <button
          key={subtype}
          type="button"
          className="ai-palette-row"
          draggable
          onDragStart={(e) => onActorDragStart(e, subtype)}
          onClick={() => addActorNode(nextPosition(), subtype)}
        >
          <span
            className="ai-palette-swatch"
            style={
              subtype === "CONSUMER"
                ? { borderStyle: "dashed", borderColor: "var(--actor-consumer)" }
                : undefined
            }
          />
          {TITLE_CASE[subtype]}
        </button>
      ))}

      <div className="ai-sidebar__title" style={{ marginTop: 16 }}>
        Governance
      </div>
      <button
        type="button"
        className="ai-palette-row"
        draggable
        onDragStart={onConstraintDragStart}
        onClick={() => addConstraintNode(nextPosition())}
      >
        <span className="ai-palette-swatch ai-palette-swatch--diamond" />
        Constraint
      </button>

      <p className="ai-sidebar__note">
        Palette shown for reference. Drag onto the canvas, or click to add.
        Connect nodes to create an <code>on_dependency</code> edge. More node
        types (Department, AI Model, Dataset, …) land in a later pass.
      </p>
    </aside>
  );
}
