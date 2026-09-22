import {
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  type Connection,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
} from "reactflow";
import { create } from "zustand";

import { ApiError, getConstraintCatalogue, scoreRegistry } from "../api/client";
import {
  ALL_CONSTRAINT_IDS,
  type ActorNodeData,
  type ActorSubtype,
  type CanvasNodeData,
  type ConstraintCatalogueEntry,
  type ConstraintNodeData,
  type PCSResultBlock,
  type RegistryBlockPayload,
} from "../types";

let nextId = 1;
const freshId = (prefix: string) => `${prefix}-${nextId++}`;

interface CanvasState {
  nodes: Node<CanvasNodeData>[];
  edges: Edge[];
  selectedNodeId: string | null;
  catalogue: ConstraintCatalogueEntry[];
  scoreResult: PCSResultBlock | null;
  scoreWarnings: string[];
  scoring: boolean;
  scoreError: string | null;

  onNodesChange: (changes: NodeChange[]) => void;
  onEdgesChange: (changes: EdgeChange[]) => void;
  onConnect: (connection: Connection) => void;

  addActorNode: (
    position: { x: number; y: number },
    subtype?: ActorSubtype
  ) => void;
  addConstraintNode: (position: { x: number; y: number }) => void;
  updateNodeData: (id: string, data: Partial<CanvasNodeData>) => void;
  setSelectedNode: (id: string | null) => void;

  loadCatalogue: () => Promise<void>;
  runScore: () => Promise<void>;
}

export const useCanvasStore = create<CanvasState>((set, get) => ({
  nodes: [],
  edges: [],
  selectedNodeId: null,
  catalogue: [],
  scoreResult: null,
  scoreWarnings: [],
  scoring: false,
  scoreError: null,

  onNodesChange: (changes) =>
    set((s) => ({ nodes: applyNodeChanges(changes, s.nodes) })),

  onEdgesChange: (changes) =>
    set((s) => ({ edges: applyEdgeChanges(changes, s.edges) })),

  onConnect: (connection) =>
    set((s) => ({
      edges: addEdge(
        {
          ...connection,
          type: "default",
          label: "on_dependency",
          data: { kind: "ON_DEPENDENCY" },
        },
        s.edges
      ),
    })),

  addActorNode: (position, subtype = "TRAINER") => {
    const id = freshId("actor");
    const data: ActorNodeData = {
      kind: "ACTOR",
      subtype,
      identity: "",
    };
    const node: Node<CanvasNodeData> = {
      id,
      type: "actorNode",
      position,
      data,
    };
    set((s) => ({ nodes: [...s.nodes, node], selectedNodeId: id }));
  },

  addConstraintNode: (position) => {
    const id = freshId("constraint");
    const data: ConstraintNodeData = {
      kind: "CONSTRAINT",
      constraintId: ALL_CONSTRAINT_IDS[0],
      status: "NOT_YET_DETERMINED",
      evidence: "",
    };
    const node: Node<CanvasNodeData> = {
      id,
      type: "constraintNode",
      position,
      data,
    };
    set((s) => ({ nodes: [...s.nodes, node], selectedNodeId: id }));
  },

  updateNodeData: (id, patch) =>
    set((s) => ({
      nodes: s.nodes.map((n) =>
        n.id === id
          ? ({ ...n, data: { ...n.data, ...patch } } as Node<CanvasNodeData>)
          : n
      ),
    })),

  setSelectedNode: (id) => set({ selectedNodeId: id }),

  loadCatalogue: async () => {
    try {
      const catalogue = await getConstraintCatalogue();
      set({ catalogue });
    } catch {
      // Fall back to the hardcoded ALL_CONSTRAINT_IDS list; the catalogue
      // endpoint only supplies display metadata, not scoring behavior.
    }
  },

  runScore: async () => {
    const { nodes } = get();
    set({ scoring: true, scoreError: null });

    const actors: RegistryBlockPayload["actors"] = {};
    for (const n of nodes) {
      if (n.data.kind === "ACTOR") {
        const key = n.data.subtype.toLowerCase();
        actors[key] = { identity: n.data.identity || n.id };
      }
    }

    const constraints_declared: RegistryBlockPayload["governance_state"]["constraints_declared"] =
      {};
    for (const cid of ALL_CONSTRAINT_IDS) {
      constraints_declared[cid] = { status: "NOT_YET_DETERMINED" };
    }
    for (const n of nodes) {
      if (n.data.kind === "CONSTRAINT" && n.data.constraintId) {
        constraints_declared[n.data.constraintId] = {
          status: n.data.status,
          evidence: n.data.evidence || undefined,
        };
      }
    }

    const registry: RegistryBlockPayload = {
      actors,
      governance_state: { constraints_declared },
    };

    try {
      const res = await scoreRegistry(registry);
      set({
        scoreResult: res.pcs_result,
        scoreWarnings: res.warnings,
        scoring: false,
      });
    } catch (err) {
      const message =
        err instanceof ApiError
          ? typeof err.detail === "string"
            ? err.detail
            : JSON.stringify(err.detail)
          : err instanceof Error
            ? err.message
            : "Unknown error";
      set({ scoring: false, scoreError: message, scoreResult: null });
    }
  },
}));
