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
  type AIModelNodeData,
  type CanvasNodeData,
  type ConstraintCatalogueEntry,
  type ConstraintNodeData,
  type DepartmentNodeData,
  type PCSResultBlock,
  type RegistryBlockPayload,
} from "../types";

let nextId = 1;
const freshId = (prefix: string) => `${prefix}-${nextId++}`;

const DEFAULT_DEPARTMENT_SIZE = { width: 260, height: 200 };

function absoluteRect(node: Node<CanvasNodeData>) {
  const pos = node.positionAbsolute ?? node.position;
  const width = node.width ?? (node.data.kind === "DEPARTMENT" ? DEFAULT_DEPARTMENT_SIZE.width : 190);
  const height = node.height ?? (node.data.kind === "DEPARTMENT" ? DEFAULT_DEPARTMENT_SIZE.height : 60);
  return { x: pos.x, y: pos.y, width, height };
}

function centerOf(rect: { x: number; y: number; width: number; height: number }) {
  return { x: rect.x + rect.width / 2, y: rect.y + rect.height / 2 };
}

function rectContainsPoint(
  rect: { x: number; y: number; width: number; height: number },
  point: { x: number; y: number }
) {
  return (
    point.x >= rect.x &&
    point.x <= rect.x + rect.width &&
    point.y >= rect.y &&
    point.y <= rect.y + rect.height
  );
}

// React Flow v11 requires a parent node to appear before its children in
// the nodes array. Only DEPARTMENT nodes are ever parents here, and they
// never have a parent themselves, so partitioning is enough — no need for
// a full topological sort.
function reorderParentsFirst(nodes: Node<CanvasNodeData>[]) {
  const withoutParent = nodes.filter((n) => !n.parentNode);
  const withParent = nodes.filter((n) => n.parentNode);
  return [...withoutParent, ...withParent];
}

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
  addDepartmentNode: (position: { x: number; y: number }) => void;
  addAIModelNode: (position: { x: number; y: number }) => void;
  updateNodeData: (id: string, data: Partial<CanvasNodeData>) => void;
  setSelectedNode: (id: string | null) => void;
  settleNodeParent: (nodeId: string) => void;

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

  onNodesChange: (changes) => {
    set((s) => ({ nodes: applyNodeChanges(changes, s.nodes) }));
    for (const change of changes) {
      if (change.type === "position" && change.dragging === false) {
        get().settleNodeParent(change.id);
      }
    }
  },

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
      departmentId: "",
    };
    const node: Node<CanvasNodeData> = {
      id,
      type: "actorNode",
      position,
      data,
    };
    set((s) => ({ nodes: [...s.nodes, node], selectedNodeId: id }));
  },

  addDepartmentNode: (position) => {
    const id = freshId("department");
    const data: DepartmentNodeData = {
      kind: "DEPARTMENT",
      name: "",
      reportsToDepartmentId: "",
    };
    const node: Node<CanvasNodeData> = {
      id,
      type: "departmentNode",
      position,
      style: { ...DEFAULT_DEPARTMENT_SIZE },
      data,
    };
    // Department nodes must precede any node parented to them, and they
    // can never be parents of each other visually, so appending is safe.
    set((s) => ({ nodes: [...s.nodes, node], selectedNodeId: id }));
  },

  addAIModelNode: (position) => {
    const id = freshId("ai-model");
    const data: AIModelNodeData = {
      kind: "AI_MODEL",
      name: "",
      modelType: "LLM",
      aiCriticality: "OPERATIONAL",
      domain: "",
      dataSensitivity: "INTERNAL",
      hostingEnvironment: "TYPE_1_INHOUSE",
    };
    const node: Node<CanvasNodeData> = {
      id,
      type: "aiModelNode",
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

  settleNodeParent: (nodeId) =>
    set((s) => {
      const node = s.nodes.find((n) => n.id === nodeId);
      if (!node || node.data.kind === "DEPARTMENT") return {};

      const rect = absoluteRect(node);
      const center = centerOf(rect);
      const department = s.nodes.find(
        (n) =>
          n.id !== nodeId &&
          n.data.kind === "DEPARTMENT" &&
          rectContainsPoint(absoluteRect(n), center)
      );

      const nextParentId = department?.id;
      if ((node.parentNode ?? undefined) === nextParentId) return {};

      let nodes = s.nodes.map((n): Node<CanvasNodeData> => {
        if (n.id !== nodeId) return n;

        const isActor = n.data.kind === "ACTOR";
        if (department) {
          const deptRect = absoluteRect(department);
          // No `extent: 'parent'` here on purpose: that hard-clamps drags
          // to stay inside the parent, which would make it impossible to
          // ever drag a node back out to detach it. Containment is instead
          // just a bounding-box check on drag-stop (above), same as the
          // membership model this ports from Secure Tropos's canvas.
          return {
            ...n,
            parentNode: department.id,
            position: { x: rect.x - deptRect.x, y: rect.y - deptRect.y },
            data: isActor
              ? { ...(n.data as ActorNodeData), departmentId: department.id }
              : n.data,
          };
        }
        // Dragged outside every department — detach back to a top-level node.
        const { parentNode: _parentNode, ...rest } = n;
        return {
          ...rest,
          position: { x: rect.x, y: rect.y },
          data: isActor
            ? { ...(n.data as ActorNodeData), departmentId: "" }
            : n.data,
        };
      });

      if (department) nodes = reorderParentsFirst(nodes);

      return { nodes };
    }),

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
        actors[key] = {
          identity: n.data.identity || n.id,
          department_id: n.data.departmentId || undefined,
        };
      }
    }

    const departments: RegistryBlockPayload["departments"] = [];
    for (const n of nodes) {
      if (n.data.kind === "DEPARTMENT") {
        departments.push({
          id: n.id,
          name: n.data.name || n.id,
          reports_to_department_id: n.data.reportsToDepartmentId || undefined,
        });
      }
    }

    // Only one deployment context exists per registry — the first AI Model
    // node on canvas wins if there happen to be several.
    const aiModel = nodes.find((n) => n.data.kind === "AI_MODEL")?.data as
      | AIModelNodeData
      | undefined;
    const deployment_context = aiModel
      ? {
          model_type: aiModel.modelType,
          ai_criticality: aiModel.aiCriticality,
          data_sensitivity: aiModel.dataSensitivity,
          domain: aiModel.domain,
        }
      : undefined;
    const system_type = aiModel?.hostingEnvironment;

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
      departments,
      deployment_context,
      system_type,
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
