// Shared by every node component: looks up this node's latest /assess
// verdict (Task 1.3/1.4) and returns a CSS class suffix for the risk ring,
// independent of each node type's own internal status styling (e.g. a
// Constraint node's own satisfied/unmet diamond colour). Returns "" for a
// node with no verdict yet, or none at all for its id.
import { useCanvasStore } from "./store/useCanvasStore";

export function useRiskRingClass(nodeId: string): string {
  const status = useCanvasStore((s) => s.elementStatusByNodeId[nodeId]);
  return status ? ` ai-risk-ring ai-risk-ring--${status.toLowerCase()}` : "";
}
