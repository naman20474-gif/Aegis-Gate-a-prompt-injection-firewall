export type Verdict = 'allow' | 'flag' | 'block' | 'review' | 'deny' | string;

export interface ScanSignal {
  id: string;
  category: string;
  weight: number;
  span: [number, number];
  span_start?: number | null;
  span_end?: number | null;
  excerpt: string;
}

export interface ScanResult {
  scan_id: string;
  content_id: string;
  source_type: string;
  source_id?: string | null;
  session_id?: string | null;
  risk: number;
  risk_score?: number | null;
  verdict: Verdict;
  signals: ScanSignal[];
  llm?: {
    is_injection?: boolean;
    confidence?: number;
    technique?: string | null;
    rationale?: string;
    invoked?: boolean;
    degraded?: boolean;
    tokens_used?: number;
    provider?: string;
  };
  stage_latency?: Record<string, number>;
  stage_latencies?: Record<string, number>;
  latency?: Record<string, number>;
  tokens_used?: number;
  normalized?: Record<string, unknown>;
  normalization?: Record<string, unknown>;
  hidden_signals?: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface Stats {
  evaluations?: number;
  decisions?: Record<string, number>;
  policies?: Record<string, number>;
  risk?: { average?: number; max?: number };
  approvals?: Record<string, number>;
  approvals_pending?: number;
  blocked_count?: number;
  scan_blocked_count?: number;
  allow_rate?: number;
  p50_latency_ms?: number;
  p95_latency_ms?: number;
  p50_latency?: number;
  p95_latency?: number;
  tokens_used?: number;
  events_buffered?: number;
}

export interface AuditItem {
  id?: number;
  event_id: string;
  event_type: string;
  decision_id?: string | null;
  source: string;
  action: string;
  decision: string;
  risk_score: number;
  policy: string;
  payload?: Record<string, unknown> | unknown;
  provenance?: unknown;
  matched_rules?: unknown;
  payload_json?: string;
  provenance_json?: string;
  matched_rules_json?: string;
  created_at: string;
}

export interface AuditResponse {
  items: AuditItem[];
  count: number;
}

export interface Approval {
  approval_id: string;
  decision_id: string;
  status: string;
  reason: string;
  requested_by: string;
  resolved_by?: string | null;
  resolution_note?: string | null;
  requested_at: string;
  resolved_at?: string | null;
  context_json?: string;
}

export interface ApprovalResponse {
  items: Approval[];
  count: number;
}

export interface ToolDecision {
  action: string;
  rule_id: string;
  reason: string;
  evidence: string;
  approval_id?: string | null;
  risk: number;
  decision_id: string;
  alert?: string | null;
}

export interface AgentRunResponse {
  session_id: string;
  status: string;
  mode: string;
  fixture_id: string;
  scan_result?: ScanResult | null;
  outbox_id?: string | null;
  tool_decision?: ToolDecision | null;
  events: string[];
}

export interface AgentEvent {
  id?: string;
  type: string;
  session_id?: string | null;
  created_at?: string;
  data: Record<string, unknown>;
}

export interface PolicyDocument {
  name?: string;
  description?: string;
  thresholds?: { review?: number; deny?: number };
  blocked_taints?: string[];
  approval_taints?: string[];
  protected_actions?: string[];
  rule_actions?: Record<string, string>;
  tool_policies?: Record<string, Record<string, unknown>>;
  global?: Record<string, unknown>;
  policies?: Array<Record<string, unknown>>;
  default?: PolicyDocument;
  [key: string]: unknown;
}

export interface BenchmarkMetrics {
  precision?: number;
  recall?: number;
  fpr?: number;
  per_category_recall?: Record<string, number>;
  p50_latency_ms?: number;
  p95_latency_ms?: number;
  tokens_per_scan?: number;
  rules_only?: Record<string, unknown>;
  rules_plus_llm?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface BenchmarkLatest {
  run_id?: string | null;
  created_at?: string | null;
  metrics?: BenchmarkMetrics | null;
}

export interface FixturesResponse {
  tools?: string[];
  fixtures?: string[];
}

export type AsyncStatus = 'idle' | 'loading' | 'success' | 'error';

export interface ResourceState<T> {
  data: T | null;
  status: AsyncStatus;
  error: string | null;
}
