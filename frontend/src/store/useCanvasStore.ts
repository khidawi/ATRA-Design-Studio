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

import {
  ApiError,
  getConstraintCatalogue,
  scoreRegistry,
  sendChatMessage as apiSendChatMessage,
} from "../api/client";
import type { ConstraintBundle } from "../constraintBundles";
import { resolveEdge } from "../edgeRules";
import { validateGraph, type ValidationIssue } from "../validation";
import {
  ALL_CONSTRAINT_IDS,
  type ActorNodeData,
  type ActorSubtype,
  type AIModelNodeData,
  type CanvasNodeData,
  type ChatMessage,
  type ConstraintCatalogueEntry,
  type ConstraintNodeData,
  type DepartmentNodeData,
  type GeneratedGraph,
  type PCSResultBlock,
  type RegistryBlockPayload,
} from "../types";

let nextId = 1;

// The six "breadth" node types added in Phase 6 all share one component
// (SimpleNode.tsx) and don't need bespoke add-actions like Actor/Constraint/
// Department/AI Model do — one factory covers all of them.
type SimpleKind =
  | "DATA_CATEGORY"
  | "CONSENT_RECORD"
  | "REGULATORY_REQ"
  | "LEGAL_BASIS"
  | "TRAINING_DATASET"
  | "DEPLOYMENT_ENV";

function defaultSimpleData(kind: SimpleKind): CanvasNodeData {
  switch (kind) {
    case "DATA_CATEGORY":
      return { kind, name: "", sensitivity: "NON_PERSONAL" };
    case "CONSENT_RECORD":
      return {
        kind,
        diaprodConsentId: "",
        validatedAt: "",
        validationSource: "MANUAL",
      };
    case "REGULATORY_REQ":
      return {
        kind,
        instrument: "",
        clause: "",
        riskTier: "",
        status: "NOT_YET_DETERMINED",
      };
    case "LEGAL_BASIS":
      return { kind, basis: "CONSENT" };
    case "TRAINING_DATASET":
      return { kind, name: "", description: "" };
    case "DEPLOYMENT_ENV":
      return { kind, name: "", description: "" };
  }
}
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

// Shared by manual drag-to-connect (onConnect) and the chatbot's generated
// edges (applyGeneratedGraph) — both are just "two node ids", and the
// canonical EdgeType/direction/label always comes from edgeRules.ts.
function buildResolvedEdge(
  nodes: Node<CanvasNodeData>[],
  sourceId: string,
  targetId: string
): Edge | null {
  const sourceNode = nodes.find((n) => n.id === sourceId);
  const targetNode = nodes.find((n) => n.id === targetId);
  if (!sourceNode || !targetNode) return null;

  const resolved = resolveEdge(sourceNode.data, targetNode.data);
  const [finalSource, finalTarget] = resolved.swapped
    ? [targetId, sourceId]
    : [sourceId, targetId];

  return {
    id: freshId("edge"),
    source: finalSource,
    target: finalTarget,
    type: "default",
    label: resolved.label,
    data: { kind: resolved.type },
  };
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

  chatMessages: ChatMessage[];
  chatOpen: boolean;
  chatLoading: boolean;
  chatError: string | null;

  validationIssues: ValidationIssue[];
  validationOpen: boolean;

  onNodesChange: (changes: NodeChange[]) => void;
  onEdgesChange: (changes: EdgeChange[]) => void;
  onConnect: (connection: Connection) => void;

  addActorNode: (
    position: { x: number; y: number },
    subtype?: ActorSubtype
  ) => void;
  addConstraintNode: (position: { x: number; y: number }) => void;
  addConstraintBundle: (
    bundle: ConstraintBundle,
    position: { x: number; y: number }
  ) => void;
  addDepartmentNode: (position: { x: number; y: number }) => void;
  addAIModelNode: (position: { x: number; y: number }) => void;
  addSimpleNode: (kind: SimpleKind, position: { x: number; y: number }) => void;
  updateNodeData: (id: string, data: Partial<CanvasNodeData>) => void;
  setSelectedNode: (id: string | null) => void;
  settleNodeParent: (nodeId: string) => void;

  loadCatalogue: () => Promise<void>;
  runScore: () => Promise<void>;

  toggleChat: () => void;
  sendChatMessage: (text: string) => Promise<void>;
  applyGeneratedGraph: (graph: GeneratedGraph) => void;

  runValidation: () => void;
  toggleValidation: () => void;
  closeValidation: () => void;
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

  chatMessages: [],
  chatOpen: false,
  chatLoading: false,
  chatError: null,

  validationIssues: [],
  validationOpen: false,

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
    set((s) => {
      const { source, target } = connection;
      if (!source || !target) return {};
      // Canonical direction (from edgeRules.ts) may run opposite to the way
      // the user actually dragged — e.g. dragging from an AI Model to its
      // Trainer still renders as Trainer --trains--> Model.
      const edge = buildResolvedEdge(s.nodes, source, target);
      if (!edge) return {};
      return { edges: addEdge(edge, s.edges) };
    }),

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

  addSimpleNode: (kind, position) => {
    const id = freshId(kind.toLowerCase().replace(/_/g, "-"));
    const node: Node<CanvasNodeData> = {
      id,
      type: "simpleNode",
      position,
      data: defaultSimpleData(kind),
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

  addConstraintBundle: (bundle, position) => {
    const newNodes: Node<CanvasNodeData>[] = bundle.constraintIds.map(
      (constraintId, i): Node<CanvasNodeData> => ({
        id: freshId("constraint"),
        type: "constraintNode",
        position: { x: position.x + i * 100, y: position.y },
        data: {
          kind: "CONSTRAINT",
          constraintId,
          status: "NOT_YET_DETERMINED",
          evidence: "",
        },
      })
    );
    set((s) => ({ nodes: [...s.nodes, ...newNodes] }));
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
    const { nodes, edges } = get();
    set({ scoring: true, scoreError: null });

    // Edges are stored in whatever direction they were resolved to, which
    // for pairs with no specific edgeRules.ts rule (e.g. Consent Record —
    // Data Category) depends on which node the user dragged from. Looking
    // both directions here is simpler and more robust than relying on a
    // canonical direction that isn't guaranteed for every pair.
    const neighborsOfKind = (nodeId: string, kind: CanvasNodeData["kind"]) => {
      const ids: string[] = [];
      for (const e of edges) {
        if (e.source === nodeId) {
          const other = nodes.find((n) => n.id === e.target);
          if (other?.data.kind === kind) ids.push(other.id);
        } else if (e.target === nodeId) {
          const other = nodes.find((n) => n.id === e.source);
          if (other?.data.kind === kind) ids.push(other.id);
        }
      }
      return ids;
    };

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

    const data_categories: RegistryBlockPayload["data_categories"] = [];
    for (const n of nodes) {
      if (n.data.kind === "DATA_CATEGORY") {
        data_categories.push({
          id: n.id,
          name: n.data.name || n.id,
          sensitivity: n.data.sensitivity,
        });
      }
    }

    const regulatory_requirements: RegistryBlockPayload["regulatory_requirements"] =
      [];
    for (const n of nodes) {
      if (n.data.kind === "REGULATORY_REQ") {
        regulatory_requirements.push({
          id: n.id,
          instrument: n.data.instrument || n.id,
          clause: n.data.clause,
          risk_tier: n.data.riskTier || undefined,
          status: n.data.status,
        });
      }
    }

    const consent_records: RegistryBlockPayload["consent_records"] = [];
    for (const n of nodes) {
      if (n.data.kind !== "CONSENT_RECORD") continue;
      const legalBasisId = neighborsOfKind(n.id, "LEGAL_BASIS")[0];
      const legalBasisNode = legalBasisId
        ? nodes.find((x) => x.id === legalBasisId)
        : undefined;
      const legalBasis =
        legalBasisNode?.data.kind === "LEGAL_BASIS"
          ? legalBasisNode.data.basis
          : "";
      consent_records.push({
        id: n.id,
        diaprod_consent_id: n.data.diaprodConsentId || undefined,
        legal_basis: legalBasis,
        data_category_ids: neighborsOfKind(n.id, "DATA_CATEGORY"),
        validated_at: n.data.validatedAt || undefined,
        validation_source: n.data.validationSource,
      });
    }

    const registry: RegistryBlockPayload = {
      actors,
      departments,
      deployment_context,
      system_type,
      data_categories,
      consent_records,
      regulatory_requirements,
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

  toggleChat: () => set((s) => ({ chatOpen: !s.chatOpen })),

  runValidation: () => {
    const { nodes, edges } = get();
    set({ validationIssues: validateGraph(nodes, edges), validationOpen: true });
  },

  toggleValidation: () => set((s) => ({ validationOpen: !s.validationOpen })),

  closeValidation: () => set({ validationOpen: false }),

  sendChatMessage: async (text) => {
    const userMessage: ChatMessage = { role: "user", content: text };
    set((s) => ({
      chatMessages: [...s.chatMessages, userMessage],
      chatLoading: true,
      chatError: null,
    }));

    try {
      const history = get().chatMessages.slice(0, -1); // history before this turn
      const graph = await apiSendChatMessage(text, history);
      get().applyGeneratedGraph(graph);
      set((s) => ({
        chatMessages: [
          ...s.chatMessages,
          { role: "assistant", content: graph.reply },
        ],
        chatLoading: false,
      }));
    } catch (err) {
      const message =
        err instanceof ApiError
          ? typeof err.detail === "string"
            ? err.detail
            : JSON.stringify(err.detail)
          : err instanceof Error
            ? err.message
            : "Unknown error";
      set({ chatLoading: false, chatError: message });
    }
  },

  applyGeneratedGraph: (graph) => {
    const DEPT_GAP_X = 300;
    const DEPT_BASE_X = 60;
    const DEPT_BASE_Y = 60;
    const ACTOR_ROW_H = 70;
    const MODEL_GAP_Y = 220;
    const CONSTRAINT_GAP_X = 100;

    const tempIdToRealId = new Map<string, string>();
    const newNodes: Node<CanvasNodeData>[] = [];

    // Departments first — position left-to-right, sized to fit however
    // many actors will end up nested inside once actors are placed below.
    const actorsByDept = new Map<string, typeof graph.actors>();
    const looseActors: typeof graph.actors = [];
    for (const a of graph.actors) {
      if (a.department_temp_id && graph.departments.some((d) => d.temp_id === a.department_temp_id)) {
        const list = actorsByDept.get(a.department_temp_id) ?? [];
        list.push(a);
        actorsByDept.set(a.department_temp_id, list);
      } else {
        looseActors.push(a);
      }
    }

    const deptOrigin = new Map<string, { x: number; y: number; height: number }>();
    graph.departments.forEach((d, i) => {
      const id = freshId("department");
      tempIdToRealId.set(d.temp_id, id);
      const count = actorsByDept.get(d.temp_id)?.length ?? 0;
      const height = Math.max(DEFAULT_DEPARTMENT_SIZE.height, 60 + count * ACTOR_ROW_H + 20);
      const x = DEPT_BASE_X + i * DEPT_GAP_X;
      const y = DEPT_BASE_Y;
      deptOrigin.set(d.temp_id, { x, y, height });
      newNodes.push({
        id,
        type: "departmentNode",
        position: { x, y },
        style: { width: DEFAULT_DEPARTMENT_SIZE.width, height },
        data: { kind: "DEPARTMENT", name: d.name, reportsToDepartmentId: "" },
      });
    });
    // Second pass: reports_to_temp_id may reference a department defined
    // later in the array, so resolve it only once every id is known.
    graph.departments.forEach((d) => {
      if (!d.reports_to_temp_id) return;
      const realId = tempIdToRealId.get(d.temp_id);
      const parentRealId = tempIdToRealId.get(d.reports_to_temp_id);
      const node = newNodes.find((n) => n.id === realId);
      if (node && parentRealId && node.data.kind === "DEPARTMENT") {
        node.data = { ...node.data, reportsToDepartmentId: parentRealId };
      }
    });

    // Actors nested in a department: stacked vertically, positioned
    // relative to the parent (React Flow requires this once parentNode is set).
    for (const [deptTempId, actors] of actorsByDept) {
      const deptRealId = tempIdToRealId.get(deptTempId)!;
      actors.forEach((a, i) => {
        const id = freshId("actor");
        tempIdToRealId.set(a.temp_id, id);
        newNodes.push({
          id,
          type: "actorNode",
          parentNode: deptRealId,
          position: { x: 20, y: 50 + i * ACTOR_ROW_H },
          data: {
            kind: "ACTOR",
            subtype: a.subtype,
            identity: a.identity,
            departmentId: deptRealId,
          },
        });
      });
    }

    // Actors with no department: a free row below the department band.
    const belowDeptsY =
      DEPT_BASE_Y +
      Math.max(DEFAULT_DEPARTMENT_SIZE.height, ...[...deptOrigin.values()].map((o) => o.height), 0) +
      60;
    looseActors.forEach((a, i) => {
      const id = freshId("actor");
      tempIdToRealId.set(a.temp_id, id);
      newNodes.push({
        id,
        type: "actorNode",
        position: { x: DEPT_BASE_X + i * 210, y: belowDeptsY },
        data: {
          kind: "ACTOR",
          subtype: a.subtype,
          identity: a.identity,
          departmentId: "",
        },
      });
    });

    // AI Models: a column to the right of the department band.
    const modelsX =
      graph.departments.length > 0
        ? DEPT_BASE_X + graph.departments.length * DEPT_GAP_X
        : DEPT_BASE_X;
    graph.ai_models.forEach((m, i) => {
      const id = freshId("ai-model");
      tempIdToRealId.set(m.temp_id, id);
      newNodes.push({
        id,
        type: "aiModelNode",
        position: { x: modelsX, y: DEPT_BASE_Y + i * MODEL_GAP_Y },
        data: {
          kind: "AI_MODEL",
          name: m.name,
          modelType: m.model_type,
          aiCriticality: m.ai_criticality,
          domain: m.domain,
          dataSensitivity: m.data_sensitivity,
          hostingEnvironment: m.hosting_environment,
        },
      });
    });

    // Constraints: a row beneath everything else.
    const constraintsY = belowDeptsY + (looseActors.length > 0 ? 120 : 0);
    graph.constraints.forEach((c, i) => {
      const id = freshId("constraint");
      tempIdToRealId.set(c.temp_id, id);
      newNodes.push({
        id,
        type: "constraintNode",
        position: { x: DEPT_BASE_X + i * CONSTRAINT_GAP_X, y: constraintsY },
        data: {
          kind: "CONSTRAINT",
          constraintId: c.constraint_id,
          status: c.status,
          evidence: c.evidence,
        },
      });
    });

    set((s) => {
      const allNodes = reorderParentsFirst([...s.nodes, ...newNodes]);

      const newEdges: Edge[] = [];
      for (const e of graph.edges) {
        const sourceId = tempIdToRealId.get(e.from_temp_id);
        const targetId = tempIdToRealId.get(e.to_temp_id);
        // Silently drop edges referencing a temp_id the model didn't
        // actually define a node for, rather than failing the whole turn.
        if (!sourceId || !targetId) continue;
        const edge = buildResolvedEdge(allNodes, sourceId, targetId);
        if (edge) newEdges.push(edge);
      }

      return { nodes: allNodes, edges: [...s.edges, ...newEdges] };
    });
  },
}));
