// The canvas analogue of Secure Tropos's analysis.js structural checks
// (dangling nodes, duplicate objects, unsatisfied constraints) — run
// entirely client-side against the current canvas state, no round trip.
// Scoped to what's actually true of THIS schema rather than porting their
// checks wholesale: e.g. "unsatisfied constraint" here specifically means
// the evidence-required-for-SATISFIED rule schema.py enforces server-side,
// not a generic notion of satisfaction Secure Tropos's model had.
import type { Edge, Node } from "reactflow";
import type { CanvasNodeData } from "./types";

export interface ValidationIssue {
  severity: "warning" | "error";
  message: string;
  nodeId?: string;
}

// Node kinds whose entire purpose is to be referenced by something else —
// a Department is a legitimate free-standing container, but a Data
// Category nobody points to is very likely just forgotten.
const SHOULD_BE_CONNECTED: CanvasNodeData["kind"][] = [
  "ACTOR",
  "AI_MODEL",
  "CONSTRAINT",
  "DATA_CATEGORY",
  "CONSENT_RECORD",
  "REGULATORY_REQ",
  "LEGAL_BASIS",
  "TRAINING_DATASET",
  "DEPLOYMENT_ENV",
];

const KIND_LABEL: Record<string, string> = {
  ACTOR: "Actor",
  AI_MODEL: "AI Model",
  CONSTRAINT: "Constraint",
  DATA_CATEGORY: "Data Category",
  CONSENT_RECORD: "Consent Record",
  REGULATORY_REQ: "Regulatory Requirement",
  LEGAL_BASIS: "Legal Basis",
  TRAINING_DATASET: "Training Dataset",
  DEPLOYMENT_ENV: "Deployment Environment",
};

export function validateGraph(
  nodes: Node<CanvasNodeData>[],
  edges: Edge[]
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  const connectedIds = new Set<string>();
  for (const e of edges) {
    connectedIds.add(e.source);
    connectedIds.add(e.target);
  }

  for (const n of nodes) {
    if (
      SHOULD_BE_CONNECTED.includes(n.data.kind) &&
      !n.parentNode &&
      !connectedIds.has(n.id)
    ) {
      issues.push({
        severity: "warning",
        message: `${KIND_LABEL[n.data.kind]} node isn't connected to anything.`,
        nodeId: n.id,
      });
    }
  }

  const aiModels = nodes.filter((n) => n.data.kind === "AI_MODEL");
  if (aiModels.length > 1) {
    for (const n of aiModels.slice(1)) {
      issues.push({
        severity: "warning",
        message:
          "Multiple AI Model nodes on canvas — only the first feeds registry.deployment_context.",
        nodeId: n.id,
      });
    }
  }

  const actorsBySubtype = new Map<string, Node<CanvasNodeData>[]>();
  for (const n of nodes) {
    if (n.data.kind !== "ACTOR") continue;
    const list = actorsBySubtype.get(n.data.subtype) ?? [];
    list.push(n);
    actorsBySubtype.set(n.data.subtype, list);
  }
  for (const [subtype, list] of actorsBySubtype) {
    if (list.length > 1) {
      for (const n of list.slice(1)) {
        issues.push({
          severity: "warning",
          message: `Multiple ${subtype.toLowerCase()} actors on canvas — only one fills registry.actors.${subtype.toLowerCase()}.`,
          nodeId: n.id,
        });
      }
    }
  }

  for (const n of nodes) {
    if (
      n.data.kind === "CONSTRAINT" &&
      n.data.status === "SATISFIED" &&
      !n.data.evidence.trim()
    ) {
      issues.push({
        severity: "error",
        message: `${n.data.constraintId} is marked Satisfied with no evidence — /score will reject this.`,
        nodeId: n.id,
      });
    }
  }

  return issues;
}
