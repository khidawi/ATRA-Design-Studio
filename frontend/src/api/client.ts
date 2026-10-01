import type {
  ChatMessage,
  ComplianceDomain,
  ConstraintCatalogueEntry,
  DeploymentDescriptionPayload,
  GeneratedGraph,
  RegistryBlockPayload,
  ScoreResponse,
} from "../types";

const BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ||
  "http://localhost:8765";

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail: unknown;
    try {
      const body = await res.json();
      detail = body.detail ?? body;
    } catch {
      detail = res.statusText;
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export function getHealth(): Promise<{ status: string; timestamp: string }> {
  return request("/health");
}

export function getConstraintCatalogue(): Promise<ConstraintCatalogueEntry[]> {
  return request("/catalogue/constraints");
}

export function getDomains(): Promise<ComplianceDomain[]> {
  return request("/api/domains");
}

export function scoreRegistry(
  registry: RegistryBlockPayload
): Promise<ScoreResponse> {
  return request("/score", {
    method: "POST",
    body: JSON.stringify({ registry }),
  });
}

export function sendChatMessage(
  message: string,
  history: ChatMessage[]
): Promise<GeneratedGraph> {
  return request("/chat", {
    method: "POST",
    body: JSON.stringify({ message, history }),
  });
}

export function importDeploymentDescription(
  description: DeploymentDescriptionPayload
): Promise<GeneratedGraph> {
  return request("/api/designs/import", {
    method: "POST",
    body: JSON.stringify(description),
  });
}
