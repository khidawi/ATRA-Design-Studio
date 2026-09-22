// The canvas analogue of Secure Tropos's Pattern entity (patterns-config.ts
// in the legacy codebase): a named, reusable bundle of constraint nodes a
// user can drop onto the canvas in one action instead of adding each
// SC-xxx-1 individually. Every id here must exist in ALL_CONSTRAINT_IDS
// (types.ts) — these are curated groupings of the real 12-constraint
// catalogue, not a separate invented taxonomy.
export interface ConstraintBundle {
  id: string;
  name: string;
  description: string;
  constraintIds: string[];
}

export const CONSTRAINT_BUNDLES: ConstraintBundle[] = [
  {
    id: "gdpr-core",
    name: "GDPR Core",
    description: "DPIA, right to challenge automated decisions, and consent.",
    constraintIds: ["SC-DPIA-1", "SC-CHALL-1", "SC-CONSENT-1"],
  },
  {
    id: "eu-ai-act-high-risk",
    name: "EU AI Act — High Risk",
    description: "Human oversight, fairness/bias mapping, domain governance.",
    constraintIds: ["SC-HITL-1", "SC-MAP-1", "SC-DOMAIN-1"],
  },
  {
    id: "generative-ai",
    name: "Generative AI / LLM",
    description: "Hallucination policy, model card, operator training.",
    constraintIds: ["SC-HALLU-1", "SC-MC-1", "SC-TRAIN-1"],
  },
  {
    id: "governance-baseline",
    name: "Governance Baseline",
    description: "Value-chain liability boundary and lifecycle role separation.",
    constraintIds: ["SC-LIAB-1", "SC-RCF-1", "SC-RCF-2"],
  },
];
