import { Handle, Position, type NodeProps } from "reactflow";
import { useRiskRingClass } from "../riskStatus";
import type { CanvasNodeData } from "../types";

const LEGAL_BASIS_LABEL: Record<string, string> = {
  CONSENT: "Consent",
  CONTRACT: "Contract",
  LEGAL_OBLIGATION: "Legal Obligation",
  VITAL_INTERESTS: "Vital Interests",
  PUBLIC_TASK: "Public Task",
  LEGITIMATE_INTERESTS: "Legitimate Interests",
};

// One shared shape for the "breadth" node types added in Phase 6 — a
// compact card, colour-coded per kind, rather than a bespoke component
// per type. Mirrors how Secure Tropos used one generic icon-based shape
// for its whole 35-concept catalogue.
interface Presenter {
  accent: string;
  kicker: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  title: (d: any) => string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  subtitle: (d: any) => string;
}

const PRESENTERS: Partial<Record<CanvasNodeData["kind"], Presenter>> = {
  DATA_CATEGORY: {
    accent: "data-category",
    kicker: "Data Category",
    title: (d) => d.name || "(unnamed)",
    subtitle: (d) => d.sensitivity,
  },
  CONSENT_RECORD: {
    accent: "consent-record",
    kicker: "Consent Record",
    title: (d) => d.diaprodConsentId || "(unnamed)",
    subtitle: (d) => d.validationSource,
  },
  REGULATORY_REQ: {
    accent: "regulatory-req",
    kicker: "Regulatory Requirement",
    title: (d) => d.instrument || "(unnamed)",
    subtitle: (d) => d.clause || d.status,
  },
  LEGAL_BASIS: {
    accent: "legal-basis",
    kicker: "Legal Basis",
    title: (d) => LEGAL_BASIS_LABEL[d.basis],
    subtitle: () => "GDPR Art. 6(1)",
  },
  TRAINING_DATASET: {
    accent: "training-dataset",
    kicker: "Training Dataset",
    title: (d) => d.name || "(unnamed)",
    subtitle: () => "presentational only",
  },
  DEPLOYMENT_ENV: {
    accent: "deployment-env",
    kicker: "Deployment Environment",
    title: (d) => d.name || "(unnamed)",
    subtitle: () => "presentational only",
  },
};

export default function SimpleNode({ id, data, selected }: NodeProps<CanvasNodeData>) {
  const presenter = PRESENTERS[data.kind];
  const riskClass = useRiskRingClass(id);
  if (!presenter) return null;

  return (
    <div
      className={`ai-simple-node ai-simple-node--${presenter.accent}${
        selected ? " ai-simple-node--selected" : ""
      }${riskClass}`}
    >
      <Handle type="target" position={Position.Top} />
      <div className="ai-simple-node__kicker">{presenter.kicker}</div>
      <div className="ai-simple-node__title">{presenter.title(data)}</div>
      <div className="ai-simple-node__subtitle">{presenter.subtitle(data)}</div>
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}
