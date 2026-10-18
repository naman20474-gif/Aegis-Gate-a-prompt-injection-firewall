import type {
  AgentEvent,
  AgentRunResponse,
  Approval,
  ApprovalResponse,
  AuditResponse,
  BenchmarkLatest,
  FixturesResponse,
  PolicyDocument,
  ScanResult,
  Stats,
} from './types';

const jsonHeaders = { 'Content-Type': 'application/json' };

export class ApiError extends Error {
  status: number;

  constructor(message: string, status = 0) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      Accept: 'application/json',
      ...(init?.body ? jsonHeaders : {}),
      ...init?.headers,
    },
  });
  if (!response.ok) {
    let detail = `Request failed (${response.status})`;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      // Keep the status-based error when the server did not return JSON.
    }
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}

export const api = {
  stats: () => request<Stats>('/api/stats'),
  audit: (limit = 80) => request<AuditResponse>(`/api/audit?limit=${limit}`),
  auditDetail: (eventId: string) => request<Record<string, unknown>>(`/api/audit/${encodeURIComponent(eventId)}`),
  policies: () => request<PolicyDocument>('/api/policies'),
  updatePolicies: (policy: PolicyDocument) =>
    request<{ updated: boolean; policy: PolicyDocument }>('/api/policies', {
      method: 'PUT',
      body: JSON.stringify(policy),
    }),
  approvals: (status?: string) => {
    const query = status ? `?status=${encodeURIComponent(status)}` : '';
    return request<ApprovalResponse>(`/api/approvals${query}`);
  },
  decideApproval: (approvalId: string, decision: 'approve' | 'deny') =>
    request<Approval>(`/api/approvals/${encodeURIComponent(approvalId)}`, {
      method: 'POST',
      body: JSON.stringify({ decision, resolved_by: 'operator' }),
    }),
  benchmark: () => request<BenchmarkLatest>('/api/bench/latest'),
  runBenchmark: () => request<BenchmarkLatest & { total?: number; passed?: number }>('/api/bench/run', { method: 'POST' }),
  fixtures: () => request<FixturesResponse>('/api/v1/agent/tools'),
  scan: (content: string, sourceType = 'control-center') =>
    request<ScanResult>('/api/scan', {
      method: 'POST',
      body: JSON.stringify({ content, source_type: sourceType }),
    }),
  runAgent: (payload: { task: string; fixture_id: string; mode: 'protected' | 'unprotected' }) =>
    request<AgentRunResponse>('/api/agent/run', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};

export function subscribeToSession(
  sessionId: string,
  onEvent: (event: AgentEvent) => void,
  onError?: () => void,
): () => void {
  const source = new EventSource(`/api/stream/${encodeURIComponent(sessionId)}?limit=100`);
  const eventTypes = [
    'content_ingested',
    'scan_result',
    'tool_proposed',
    'policy_decision',
    'approval_requested',
    'tool_executed',
    'run_finished',
  ];
  const handlers = eventTypes.map((type) => {
    const handler = (event: MessageEvent<string>) => {
      try {
        onEvent({
          id: event.lastEventId,
          type,
          data: JSON.parse(event.data) as Record<string, unknown>,
        });
      } catch {
        onEvent({ id: event.lastEventId, type, data: { raw: event.data } });
      }
    };
    source.addEventListener(type, handler);
    return { type, handler };
  });
  source.onerror = () => {
    onError?.();
    source.close();
  };
  return () => {
    handlers.forEach(({ type, handler }) => source.removeEventListener(type, handler));
    source.close();
  };
}
