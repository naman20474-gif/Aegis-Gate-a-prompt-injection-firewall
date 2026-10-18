import * as React from 'react';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowUpRight,
  BarChart3,
  Bell,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDot,
  ClipboardCheck,
  Command,
  FileCheck2,
  FileText,
  Gauge,
  GitBranch,
  KeyRound,
  Layers3,
  LayoutDashboard,
  Loader2,
  LockKeyhole,
  Menu,
  Play,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  Sparkles,
  TerminalSquare,
  Timer,
  X,
  Zap,
} from 'lucide-react';
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion';
import {
  api,
  ApiError,
  subscribeToSession,
} from './api';
import type {
  AgentEvent,
  AgentRunResponse,
  Approval,
  AuditItem,
  BenchmarkLatest,
  BenchmarkMetrics,
  PolicyDocument,
  ResourceState,
  ScanResult,
  Stats,
} from './types';

type Section = 'overview' | 'audit' | 'policies' | 'approvals' | 'bench';
type RunMode = 'protected' | 'unprotected';

interface RunState {
  response: AgentRunResponse;
  events: AgentEvent[];
}

interface ResourceErrors {
  stats: string | null;
  audit: string | null;
  policies: string | null;
  approvals: string | null;
  benchmark: string | null;
  fixtures: string | null;
}

const EMPTY_ERRORS: ResourceErrors = {
  stats: null,
  audit: null,
  policies: null,
  approvals: null,
  benchmark: null,
  fixtures: null,
};

const navItems: Array<{ id: Section; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'audit', label: 'Audit stream', icon: Activity },
  { id: 'policies', label: 'Policy rules', icon: SlidersHorizontal },
  { id: 'approvals', label: 'Approvals', icon: ClipboardCheck },
  { id: 'bench', label: 'Benchmark', icon: BarChart3 },
];

const stageNames = ['ingest', 'normalize', 'rules', 'score', 'decision'];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function formatMetric(value: number | null | undefined, suffix = ''): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return `${new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(value)}${suffix}`;
}

function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return `${(value * 100).toFixed(value === 1 || value === 0 ? 0 : 1)}%`;
}

function formatTime(value: string | undefined | null): string {
  if (!value) return 'time unavailable';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(date);
}

function formatDate(value: string | undefined | null): string {
  if (!value) return 'date unavailable';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function titleCase(value: string): string {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function verdictTone(verdict: string | undefined): 'allow' | 'flag' | 'block' | 'neutral' {
  if (verdict === 'allow' || verdict === 'approved' || verdict === 'completed') return 'allow';
  if (verdict === 'flag' || verdict === 'review' || verdict === 'approval_required' || verdict === 'pending') return 'flag';
  if (verdict === 'block' || verdict === 'deny' || verdict === 'denied' || verdict === 'rejected') return 'block';
  return 'neutral';
}

function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error) return error.message;
  return 'The API did not respond.';
}

function extractScan(item: AuditItem): ScanResult | null {
  if (item.event_type !== 'scan') return null;
  const payload = item.payload;
  if (!isRecord(payload)) return null;
  if (typeof payload.scan_id !== 'string' || typeof payload.verdict !== 'string') return null;
  return payload as unknown as ScanResult;
}

function StatusDot({ tone = 'neutral', pulse = false }: { tone?: string; pulse?: boolean }) {
  return <span aria-hidden="true" className={`status-dot status-dot-${tone} ${pulse ? 'status-dot-pulse' : ''}`} />;
}

function VerdictBadge({ value, compact = false }: { value?: string | null; compact?: boolean }) {
  const tone = verdictTone(value ?? undefined);
  const label = value ? titleCase(value) : 'No verdict';
  return (
    <span className={`verdict-badge verdict-${tone} ${compact ? 'verdict-compact' : ''}`}>
      <StatusDot tone={tone} />
      {label}
    </span>
  );
}

function PanelHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="panel-header">
      <div>
        {eyebrow && <p className="eyebrow">{eyebrow}</p>}
        <h2 className="panel-title">{title}</h2>
        {description && <p className="panel-description">{description}</p>}
      </div>
      {action && <div className="panel-action">{action}</div>}
    </div>
  );
}

function LoadingState({ label = 'Loading telemetry' }: { label?: string }) {
  return (
    <div className="state-row" role="status">
      <Loader2 className="spin" size={16} aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

function EmptyState({ label, detail }: { label: string; detail?: string }) {
  return (
    <div className="empty-state">
      <CircleDot size={17} aria-hidden="true" />
      <span>{label}</span>
      {detail && <small>{detail}</small>}
    </div>
  );
}

function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={17} aria-hidden="true" />
      <span>{message}</span>
      {onRetry && (
        <button className="text-button" type="button" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

function Sparkline({ points, label }: { points: number[]; label: string }) {
  if (points.length < 2) {
    return <div className="sparkline-empty" aria-label={`${label}: no telemetry yet`}><span>No telemetry yet</span></div>;
  }
  const width = 220;
  const height = 52;
  const max = Math.max(...points, 1);
  const min = Math.min(...points, 0);
  const range = Math.max(max - min, 1);
  const path = points.map((point, index) => {
    const x = (index / (points.length - 1)) * width;
    const y = height - ((point - min) / range) * (height - 8) - 4;
    return `${index === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
  }).join(' ');
  return (
    <svg className="sparkline" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={label} preserveAspectRatio="none">
      <path d="M 0 48 H 220" className="sparkline-base" />
      <path d={path} className="sparkline-path" />
    </svg>
  );
}

function RiskGauge({ scan }: { scan: ScanResult | null }) {
  const risk = scan?.risk;
  const circumference = 2 * Math.PI * 48;
  const offset = risk === undefined ? circumference : circumference - (Math.max(0, Math.min(100, risk)) / 100) * circumference;
  return (
    <div className="gauge-wrap">
      <svg className="risk-gauge" viewBox="0 0 120 120" role="img" aria-label={risk === undefined ? 'Risk score unavailable' : `Risk score ${risk}`}>
        <circle className="gauge-track" cx="60" cy="60" r="48" />
        <circle className="gauge-value" cx="60" cy="60" r="48" strokeDasharray={circumference} strokeDashoffset={offset} />
      </svg>
      <div className="gauge-center">
        <strong>{risk === undefined ? '—' : risk}</strong>
        <span>risk</span>
      </div>
    </div>
  );
}

function MetricTile({
  label,
  value,
  detail,
  icon: Icon,
  tone = 'neutral',
}: {
  label: string;
  value: string;
  detail?: string;
  icon: typeof Activity;
  tone?: string;
}) {
  return (
    <div className="metric-tile">
      <div className="metric-topline">
        <span className="metric-label">{label}</span>
        <Icon size={15} className={`metric-icon metric-icon-${tone}`} aria-hidden="true" />
      </div>
      <strong className="metric-value">{value}</strong>
      {detail && <span className="metric-detail">{detail}</span>}
    </div>
  );
}

function App() {
  const reduceMotion = useReducedMotion();
  const [activeSection, setActiveSection] = React.useState<Section>('overview');
  const [mobileNavOpen, setMobileNavOpen] = React.useState(false);
  const [pointer, setPointer] = React.useState({ x: 0, y: 0 });
  const [stats, setStats] = React.useState<ResourceState<Stats>>({ data: null, status: 'loading', error: null });
  const [audit, setAudit] = React.useState<ResourceState<AuditItem[]>>({ data: null, status: 'loading', error: null });
  const [policies, setPolicies] = React.useState<ResourceState<PolicyDocument>>({ data: null, status: 'loading', error: null });
  const [approvals, setApprovals] = React.useState<ResourceState<Approval[]>>({ data: null, status: 'loading', error: null });
  const [benchmark, setBenchmark] = React.useState<ResourceState<BenchmarkLatest>>({ data: null, status: 'loading', error: null });
  const [fixtures, setFixtures] = React.useState<ResourceState<string[]>>({ data: null, status: 'loading', error: null });
  const [resourceErrors, setResourceErrors] = React.useState<ResourceErrors>(EMPTY_ERRORS);
  const [latestScan, setLatestScan] = React.useState<ScanResult | null>(null);
  const [scanInput, setScanInput] = React.useState('');
  const [scanStatus, setScanStatus] = React.useState<'idle' | 'loading' | 'error'>('idle');
  const [scanError, setScanError] = React.useState<string | null>(null);
  const [fixtureId, setFixtureId] = React.useState('');
  const [task, setTask] = React.useState('Trace the request and summarize the fixture');
  const [mode, setMode] = React.useState<RunMode>('protected');
  const [agentLoading, setAgentLoading] = React.useState<RunMode | null>(null);
  const [agentError, setAgentError] = React.useState<string | null>(null);
  const [runs, setRuns] = React.useState<Partial<Record<RunMode, RunState>>>({});
  const [sessionEvents, setSessionEvents] = React.useState<AgentEvent[]>([]);
  const [commandOpen, setCommandOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState('');
  const [selectedAudit, setSelectedAudit] = React.useState<AuditItem | null>(null);
  const [selectedAuditDetail, setSelectedAuditDetail] = React.useState<Record<string, unknown> | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [approvalAction, setApprovalAction] = React.useState<string | null>(null);
  const [benchmarkLoading, setBenchmarkLoading] = React.useState(false);
  const [policyDraft, setPolicyDraft] = React.useState<PolicyDocument | null>(null);
  const [policySaving, setPolicySaving] = React.useState(false);
  const [policyMessage, setPolicyMessage] = React.useState<string | null>(null);
  const sseCleanup = React.useRef<(() => void) | null>(null);
  const scanInputRef = React.useRef<HTMLInputElement>(null);
  const commandInputRef = React.useRef<HTMLInputElement>(null);

  const loadStats = React.useCallback(async () => {
    setStats((current) => ({ ...current, status: 'loading', error: null }));
    try {
      setStats({ data: await api.stats(), status: 'success', error: null });
      setResourceErrors((current) => ({ ...current, stats: null }));
    } catch (error) {
      const message = errorMessage(error);
      setStats((current) => ({ ...current, status: 'error', error: message }));
      setResourceErrors((current) => ({ ...current, stats: message }));
    }
  }, []);

  const loadAudit = React.useCallback(async () => {
    setAudit((current) => ({ ...current, status: 'loading', error: null }));
    try {
      const response = await api.audit();
      setAudit({ data: response.items, status: 'success', error: null });
      setResourceErrors((current) => ({ ...current, audit: null }));
      const scans = response.items.map(extractScan).filter((item): item is ScanResult => item !== null);
      if (scans.length > 0) setLatestScan(scans[scans.length - 1]);
    } catch (error) {
      const message = errorMessage(error);
      setAudit((current) => ({ ...current, status: 'error', error: message }));
      setResourceErrors((current) => ({ ...current, audit: message }));
    }
  }, []);

  const loadPolicies = React.useCallback(async () => {
    setPolicies((current) => ({ ...current, status: 'loading', error: null }));
    try {
      const response = await api.policies();
      setPolicies({ data: response, status: 'success', error: null });
      setPolicyDraft(response.default ?? response);
      setResourceErrors((current) => ({ ...current, policies: null }));
    } catch (error) {
      const message = errorMessage(error);
      setPolicies((current) => ({ ...current, status: 'error', error: message }));
      setResourceErrors((current) => ({ ...current, policies: message }));
    }
  }, []);

  const loadApprovals = React.useCallback(async () => {
    setApprovals((current) => ({ ...current, status: 'loading', error: null }));
    try {
      const response = await api.approvals();
      setApprovals({ data: response.items, status: 'success', error: null });
      setResourceErrors((current) => ({ ...current, approvals: null }));
    } catch (error) {
      const message = errorMessage(error);
      setApprovals((current) => ({ ...current, status: 'error', error: message }));
      setResourceErrors((current) => ({ ...current, approvals: message }));
    }
  }, []);

  const loadBenchmark = React.useCallback(async () => {
    setBenchmark((current) => ({ ...current, status: 'loading', error: null }));
    try {
      setBenchmark({ data: await api.benchmark(), status: 'success', error: null });
      setResourceErrors((current) => ({ ...current, benchmark: null }));
    } catch (error) {
      const message = errorMessage(error);
      setBenchmark((current) => ({ ...current, status: 'error', error: message }));
      setResourceErrors((current) => ({ ...current, benchmark: message }));
    }
  }, []);

  const loadFixtures = React.useCallback(async () => {
    setFixtures((current) => ({ ...current, status: 'loading', error: null }));
    try {
      const response = await api.fixtures();
      const values = response.fixtures ?? [];
      setFixtures({ data: values, status: 'success', error: null });
      setFixtureId((current) => current || values[0] || '');
      setResourceErrors((current) => ({ ...current, fixtures: null }));
    } catch (error) {
      const message = errorMessage(error);
      setFixtures((current) => ({ ...current, status: 'error', error: message }));
      setResourceErrors((current) => ({ ...current, fixtures: message }));
    }
  }, []);

  const loadAll = React.useCallback(() => {
    void Promise.all([loadStats(), loadAudit(), loadPolicies(), loadApprovals(), loadBenchmark(), loadFixtures()]);
  }, [loadApprovals, loadAudit, loadBenchmark, loadFixtures, loadPolicies, loadStats]);

  React.useEffect(() => {
    loadAll();
    return () => sseCleanup.current?.();
  }, [loadAll]);

  React.useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommandOpen(true);
      }
      if (event.key === 'Escape') {
        setCommandOpen(false);
        setMobileNavOpen(false);
      }
    };
    window.addEventListener('keydown', listener);
    return () => window.removeEventListener('keydown', listener);
  }, []);

  React.useEffect(() => {
    if (commandOpen) {
      window.setTimeout(() => commandInputRef.current?.focus(), 20);
    }
  }, [commandOpen]);

  const refreshTelemetry = React.useCallback(() => {
    void Promise.all([loadStats(), loadAudit(), loadApprovals(), loadBenchmark()]);
  }, [loadApprovals, loadAudit, loadBenchmark, loadStats]);

  const handleScan = async () => {
    const value = scanInput.trim();
    if (!value) {
      scanInputRef.current?.focus();
      return;
    }
    setScanStatus('loading');
    setScanError(null);
    try {
      const result = await api.scan(value);
      setLatestScan(result);
      setScanStatus('idle');
      setScanInput('');
      refreshTelemetry();
    } catch (error) {
      setScanStatus('error');
      setScanError(errorMessage(error));
    }
  };

  const handleAgentRun = async (requestedMode: RunMode = mode) => {
    if (!fixtureId) return;
    sseCleanup.current?.();
    setAgentLoading(requestedMode);
    setAgentError(null);
    setSessionEvents([]);
    try {
      const response = await api.runAgent({ task: task.trim() || 'Summarize the fixture', fixture_id: fixtureId, mode: requestedMode });
      const nextRun: RunState = { response, events: [] };
      setRuns((current) => ({ ...current, [requestedMode]: nextRun }));
      if (response.scan_result) setLatestScan(response.scan_result);
      sseCleanup.current = subscribeToSession(
        response.session_id,
        (event) => {
          setSessionEvents((current) => [...current, event]);
          setRuns((current) => {
            const existing = current[requestedMode];
            if (!existing || existing.response.session_id !== response.session_id) return current;
            return { ...current, [requestedMode]: { ...existing, events: [...existing.events, event] } };
          });
        },
      );
      setAgentLoading(null);
      refreshTelemetry();
    } catch (error) {
      setAgentLoading(null);
      setAgentError(errorMessage(error));
    }
  };

  const openAudit = async (item: AuditItem) => {
    setSelectedAudit(item);
    setSelectedAuditDetail(null);
    setDetailLoading(true);
    try {
      setSelectedAuditDetail(await api.auditDetail(item.event_id));
    } catch {
      // The list item remains useful when a detail row was pruned between requests.
      setSelectedAuditDetail(null);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleApproval = async (approval: Approval, decision: 'approve' | 'deny') => {
    setApprovalAction(`${approval.approval_id}:${decision}`);
    try {
      await api.decideApproval(approval.approval_id, decision);
      await Promise.all([loadApprovals(), loadAudit(), loadStats()]);
    } catch (error) {
      setResourceErrors((current) => ({ ...current, approvals: errorMessage(error) }));
    } finally {
      setApprovalAction(null);
    }
  };

  const runBenchmark = async () => {
    setBenchmarkLoading(true);
    try {
      const result = await api.runBenchmark();
      setBenchmark({ data: result, status: 'success', error: null });
      await loadStats();
    } catch (error) {
      setBenchmark((current) => ({ ...current, status: 'error', error: errorMessage(error) }));
    } finally {
      setBenchmarkLoading(false);
    }
  };

  const savePolicy = async () => {
    if (!policyDraft) return;
    setPolicySaving(true);
    setPolicyMessage(null);
    try {
      const result = await api.updatePolicies(policyDraft);
      const value = result.policy;
      setPolicies({ data: value, status: 'success', error: null });
      setPolicyDraft(value.default ?? value);
      setPolicyMessage('Policy saved and hot-reloaded.');
    } catch (error) {
      setPolicyMessage(errorMessage(error));
    } finally {
      setPolicySaving(false);
    }
  };

  const updateRuleAction = (ruleId: string, action: string) => {
    setPolicyDraft((current) => {
      if (!current) return current;
      return { ...current, rule_actions: { ...(current.rule_actions ?? {}), [ruleId]: action } };
    });
  };

  const commandActions = [
    { id: 'scan', label: 'Focus quick scan', detail: 'Inspect an input with the active scanner', icon: Search, run: () => { setActiveSection('overview'); setCommandOpen(false); window.setTimeout(() => scanInputRef.current?.focus(), 30); } },
    { id: 'protected', label: 'Run protected agent', detail: 'Route the selected fixture through policy', icon: ShieldCheck, run: () => { setMode('protected'); setCommandOpen(false); void handleAgentRun('protected'); } },
    { id: 'unprotected', label: 'Run unprotected demo', detail: 'Compare the local bypass path', icon: ShieldX, run: () => { setMode('unprotected'); setCommandOpen(false); void handleAgentRun('unprotected'); } },
    { id: 'refresh', label: 'Refresh telemetry', detail: 'Fetch the latest API state', icon: RefreshCw, run: () => { setCommandOpen(false); refreshTelemetry(); } },
    ...navItems.slice(1).map(({ id, label, icon: Icon }) => ({ id, label: `Open ${label}`, detail: 'Navigate the control center', icon: Icon, run: () => { setActiveSection(id); setCommandOpen(false); } })),
  ].filter((action) => `${action.label} ${action.detail}`.toLowerCase().includes(commandQuery.toLowerCase()));

  const auditItems = audit.data ?? [];
  const auditRiskPoints = [...auditItems].reverse().map((item) => item.risk_score).filter((value) => typeof value === 'number');
  const selectedPolicy = policyDraft ?? policies.data?.default ?? policies.data;
  const pendingApprovals = (approvals.data ?? []).filter((approval) => approval.status === 'pending');
  const activeRun = runs[mode];

  const renderSection = () => {
    if (activeSection === 'audit') {
      return <AuditSection items={auditItems} state={audit} onRetry={loadAudit} onOpen={openAudit} />;
    }
    if (activeSection === 'policies') {
      return (
        <PoliciesSection
          state={policies}
          policy={selectedPolicy}
          onRetry={loadPolicies}
          onRuleAction={updateRuleAction}
          onChange={setPolicyDraft}
          onSave={savePolicy}
          saving={policySaving}
          message={policyMessage}
        />
      );
    }
    if (activeSection === 'approvals') {
      return <ApprovalsSection state={approvals} items={approvals.data ?? []} pending={pendingApprovals} onRetry={loadApprovals} onDecision={handleApproval} actionId={approvalAction} />;
    }
    if (activeSection === 'bench') {
      return <BenchmarkSection state={benchmark} onRetry={loadBenchmark} onRun={runBenchmark} running={benchmarkLoading} />;
    }
    return (
      <Overview
        stats={stats}
        audit={audit}
        benchmark={benchmark}
        onRetryStats={loadStats}
        onRetryAudit={loadAudit}
        onRetryBenchmark={loadBenchmark}
        fixtures={fixtures}
        latestScan={latestScan}
        auditRiskPoints={auditRiskPoints}
        scanInput={scanInput}
        setScanInput={setScanInput}
        scanStatus={scanStatus}
        scanError={scanError}
        onScan={handleScan}
        scanInputRef={scanInputRef}
        fixtureId={fixtureId}
        setFixtureId={setFixtureId}
        task={task}
        setTask={setTask}
        mode={mode}
        setMode={setMode}
        agentLoading={agentLoading}
        agentError={agentError}
        runs={runs}
        activeRun={activeRun}
        sessionEvents={sessionEvents}
        onAgentRun={handleAgentRun}
        onOpenAudit={openAudit}
        onOpenSection={setActiveSection}
        pendingApprovals={pendingApprovals}
        onDecision={handleApproval}
        approvalAction={approvalAction}
        onRunBenchmark={runBenchmark}
        benchmarkRunning={benchmarkLoading}
      />
    );
  };

  const shellStyle = {
    '--parallax-x': `${pointer.x}px`,
    '--parallax-y': `${pointer.y}px`,
  } as React.CSSProperties;

  const handlePointerMove = (event: React.PointerEvent<HTMLDivElement>) => {
    if (reduceMotion || event.pointerType === 'touch') return;
    setPointer({
      x: Math.max(-12, Math.min(12, (event.clientX / window.innerWidth - 0.5) * 24)),
      y: Math.max(-12, Math.min(12, (event.clientY / window.innerHeight - 0.5) * 24)),
    });
  };

  return (
    <div className="app-shell" style={shellStyle} onPointerMove={handlePointerMove}>
      <div className="noise-layer" aria-hidden="true" />
      <svg className="background-field" aria-hidden="true" viewBox="0 0 1440 900" preserveAspectRatio="none">
        <defs>
          <linearGradient id="fieldLine" x1="0" x2="1">
            <stop offset="0" stopColor="currentColor" stopOpacity="0" />
            <stop offset="0.5" stopColor="currentColor" stopOpacity="0.18" />
            <stop offset="1" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
          <pattern id="fieldGrid" width="80" height="80" patternUnits="userSpaceOnUse">
            <path d="M 80 0 L 0 0 0 80" fill="none" stroke="currentColor" strokeOpacity="0.06" strokeWidth="1" />
          </pattern>
        </defs>
        <rect width="1440" height="900" fill="url(#fieldGrid)" />
        <path d="M -120 520 C 300 360 510 540 780 390 S 1200 180 1560 330" fill="none" stroke="url(#fieldLine)" strokeWidth="1" />
        <path d="M -140 620 C 260 470 530 630 800 490 S 1190 300 1560 420" fill="none" stroke="url(#fieldLine)" strokeWidth="1" />
      </svg>
      <Sidebar activeSection={activeSection} setActiveSection={(section) => { setActiveSection(section); setMobileNavOpen(false); }} mobileOpen={mobileNavOpen} onClose={() => setMobileNavOpen(false)} />
      <div className="content-shell">
        <header className="topbar">
          <div className="topbar-left">
            <button className="mobile-menu-button icon-button" type="button" aria-label="Open navigation" onClick={() => setMobileNavOpen(true)}>
              <Menu size={18} aria-hidden="true" />
            </button>
            <div className="crumbs"><span className="crumb-muted">Control center</span><ChevronRight size={13} aria-hidden="true" /><span>{navItems.find((item) => item.id === activeSection)?.label}</span></div>
          </div>
          <div className="topbar-actions">
            <button className="command-trigger" type="button" onClick={() => setCommandOpen(true)} aria-label="Open command bar">
              <Command size={15} aria-hidden="true" /><span>Command bar</span><kbd>⌘ / Ctrl&nbsp; K</kbd>
            </button>
            <span className="connection-state"><StatusDot tone={resourceErrors.stats ? 'block' : 'neutral'} pulse={!resourceErrors.stats} />{resourceErrors.stats ? 'API unavailable' : 'API connected'}</span>
            <button className="icon-button" type="button" aria-label="Refresh telemetry" onClick={refreshTelemetry}><RefreshCw size={16} aria-hidden="true" /></button>
          </div>
        </header>
        <main className="main-content">
          <div className="page-heading">
            <div>
              <p className="eyebrow"><span className="live-marker" /> AEGIS GATE / RUNTIME SAFETY</p>
              <h1>Security control center</h1>
              <p className="page-subtitle">Observe the policy boundary before an agent can turn content into action.</p>
            </div>
            <div className="heading-meta">
              <div><span className="meta-label">policy</span><strong>{selectedPolicy?.name ?? '—'}</strong></div>
              <div><span className="meta-label">stream</span><strong>{sessionEvents.length > 0 ? 'live' : 'standby'}</strong></div>
            </div>
          </div>
          {resourceErrors.stats && <div className="global-error"><AlertTriangle size={16} aria-hidden="true" /><span>Telemetry is unavailable: {resourceErrors.stats}</span><button type="button" className="text-button" onClick={loadStats}>Retry</button></div>}
          {renderSection()}
        </main>
      </div>
      <AnimatePresence>
        {commandOpen && (
          <CommandDialog
            query={commandQuery}
            setQuery={setCommandQuery}
            actions={commandActions}
            inputRef={commandInputRef}
            onClose={() => { setCommandOpen(false); setCommandQuery(''); }}
          />
        )}
      </AnimatePresence>
      <AnimatePresence>
        {selectedAudit && (
          <AuditSheet item={selectedAudit} detail={selectedAuditDetail} loading={detailLoading} onClose={() => setSelectedAudit(null)} />
        )}
      </AnimatePresence>
      {!reduceMotion && <div className="corner-orbit" aria-hidden="true" />}
    </div>
  );
}

function Sidebar({
  activeSection,
  setActiveSection,
  mobileOpen,
  onClose,
}: {
  activeSection: Section;
  setActiveSection: (section: Section) => void;
  mobileOpen: boolean;
  onClose: () => void;
}) {
  return (
    <>
      <button className={`nav-scrim ${mobileOpen ? 'nav-scrim-visible' : ''}`} type="button" aria-label="Close navigation" onClick={onClose} />
      <aside className={`sidebar ${mobileOpen ? 'sidebar-open' : ''}`} aria-label="Primary navigation">
        <div className="brand-mark" aria-label="Aegis Gate"><span className="brand-shield"><ShieldCheck size={19} strokeWidth={1.7} aria-hidden="true" /></span><span className="brand-copy">AEGIS<br /><b>GATE</b></span></div>
        <nav className="nav-list">
          <span className="nav-label">Workspace</span>
          {navItems.map(({ id, label, icon: Icon }) => (
            <button key={id} type="button" className={`nav-item ${activeSection === id ? 'nav-item-active' : ''}`} onClick={() => setActiveSection(id)} aria-current={activeSection === id ? 'page' : undefined}>
              <Icon size={18} strokeWidth={1.7} aria-hidden="true" /><span>{label}</span>{id === 'approvals' && <span className="nav-rail-dot" aria-hidden="true" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="operator-card"><span className="operator-avatar">OP</span><div><strong>Operator</strong><small>Local workspace</small></div><ChevronDown size={14} aria-hidden="true" /></div>
          <div className="sidebar-status"><StatusDot tone="neutral" pulse /><span>Gateway ready</span></div>
        </div>
      </aside>
    </>
  );
}

function Overview({
  stats,
  audit,
  benchmark,
  fixtures,
  latestScan,
  auditRiskPoints,
  scanInput,
  setScanInput,
  scanStatus,
  scanError,
  onScan,
  scanInputRef,
  fixtureId,
  setFixtureId,
  task,
  setTask,
  mode,
  setMode,
  agentLoading,
  agentError,
  runs,
  activeRun,
  sessionEvents,
  onAgentRun,
  onOpenAudit,
  onOpenSection,
  pendingApprovals,
  onDecision,
  approvalAction,
  onRunBenchmark,
  benchmarkRunning,
  onRetryStats,
  onRetryAudit,
  onRetryBenchmark,
}: {
  stats: ResourceState<Stats>;
  audit: ResourceState<AuditItem[]>;
  benchmark: ResourceState<BenchmarkLatest>;
  onRetryStats: () => void;
  onRetryAudit: () => void;
  onRetryBenchmark: () => void;
  fixtures: ResourceState<string[]>;
  latestScan: ScanResult | null;
  auditRiskPoints: number[];
  scanInput: string;
  setScanInput: (value: string) => void;
  scanStatus: 'idle' | 'loading' | 'error';
  scanError: string | null;
  onScan: () => void;
  scanInputRef: React.RefObject<HTMLInputElement>;
  fixtureId: string;
  setFixtureId: (value: string) => void;
  task: string;
  setTask: (value: string) => void;
  mode: RunMode;
  setMode: (value: RunMode) => void;
  agentLoading: RunMode | null;
  agentError: string | null;
  runs: Partial<Record<RunMode, RunState>>;
  activeRun?: RunState;
  sessionEvents: AgentEvent[];
  onAgentRun: (mode?: RunMode) => void;
  onOpenAudit: (item: AuditItem) => void;
  onOpenSection: (section: Section) => void;
  pendingApprovals: Approval[];
  onDecision: (approval: Approval, decision: 'approve' | 'deny') => void;
  approvalAction: string | null;
  onRunBenchmark: () => void;
  benchmarkRunning: boolean;
}) {
  const data = stats.data;
  const firstError = stats.error || audit.error || fixtures.error;
  return (
    <div className="dashboard-grid">
      <section className="panel panel-scan composer-panel grid-span-12">
        <div className="composer-icon"><Zap size={17} aria-hidden="true" /></div>
        <div className="composer-copy"><span className="eyebrow">QUICK SCAN</span><strong>Inspect inbound content</strong><span>Send a sample through the deterministic boundary and inspect the verdict.</span></div>
        <div className="composer-form">
          <label className="sr-only" htmlFor="quick-scan">Content to inspect</label>
          <input ref={scanInputRef} id="quick-scan" className="text-input" value={scanInput} onChange={(event) => setScanInput(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') void onScan(); }} placeholder="Paste a message, tool request, or document fragment…" />
          <button type="button" className="button button-primary" onClick={onScan} disabled={scanStatus === 'loading'}>{scanStatus === 'loading' ? <Loader2 size={16} className="spin" aria-hidden="true" /> : <Search size={16} aria-hidden="true" />}<span>Scan</span></button>
        </div>
        {scanError && <div className="inline-error"><AlertCircle size={14} aria-hidden="true" />{scanError}</div>}
      </section>

      <section className="panel panel-hero grid-span-5">
        <PanelHeader eyebrow="LATEST DECISION" title="Risk posture" description={latestScan ? `Source ${latestScan.source_id || latestScan.content_id}` : 'Run a scan to populate the posture view.'} action={latestScan && <VerdictBadge value={latestScan.verdict} />} />
        <div className="risk-hero">
          <RiskGauge scan={latestScan} />
          <div className="risk-copy">
            <span className="metric-label">Current exposure</span>
            <strong>{latestScan ? titleCase(latestScan.verdict) : 'Awaiting telemetry'}</strong>
            <span>{latestScan ? `${latestScan.signals.length} matched signal${latestScan.signals.length === 1 ? '' : 's'}` : 'No scan response available'}</span>
          </div>
        </div>
        <div className="signal-strip">
          {(latestScan?.signals ?? []).slice(0, 4).map((signal) => <span key={`${signal.id}-${signal.span[0]}`} className="signal-chip"><span>{titleCase(signal.category)}</span><b>{formatMetric(signal.weight)}</b></span>)}
          {latestScan && latestScan.signals.length === 0 && <span className="signal-chip signal-chip-muted">No matched signals</span>}
          {!latestScan && <span className="signal-chip signal-chip-muted">No signal telemetry</span>}
        </div>
      </section>

      <section className="panel panel-stat-cluster grid-span-7">
        <PanelHeader eyebrow="GATEWAY TELEMETRY" title="Operational pulse" action={<span className="panel-live"><StatusDot tone="neutral" pulse />Live</span>} />
        {stats.status === 'loading' && !data ? <LoadingState /> : stats.error ? <ErrorState message={stats.error} onRetry={onRetryStats} /> : (
          <div className="metric-grid">
            <MetricTile label="Allow rate" value={formatPercent(data?.allow_rate)} detail="scan verdicts" icon={ShieldCheck} tone="neutral" />
            <MetricTile label="Blocked" value={formatMetric(data?.blocked_count)} detail="policy events" icon={ShieldX} tone="neutral" />
            <MetricTile label="P95 latency" value={formatMetric(data?.p95_latency_ms ?? data?.p95_latency, ' ms')} detail="scan path" icon={Timer} tone="neutral" />
            <MetricTile label="Pending approvals" value={formatMetric(data?.approvals_pending)} detail="operator queue" icon={ClipboardCheck} tone="neutral" />
          </div>
        )}
        <div className="pulse-footer"><div><span className="metric-label">Risk trend</span><strong>{formatMetric(data?.risk?.average)} <small>avg score</small></strong></div><Sparkline points={auditRiskPoints} label="Risk score over recent audit events" /></div>
      </section>

      <section className="panel panel-pipeline grid-span-7">
        <PanelHeader eyebrow="DECISION PIPELINE" title="Boundary depth" description="Latency planes from the latest scan response." action={<GitBranch size={17} aria-hidden="true" className="panel-mark" />} />
        {latestScan ? <Pipeline scan={latestScan} /> : <EmptyState label="No pipeline response" detail="The stage breakdown will appear after a scan." />}
      </section>

      <section className="panel panel-agent grid-span-5">
        <PanelHeader eyebrow="AGENT LAB" title="Protected / unprotected" description="Run the same fixture through two execution boundaries." action={<TerminalSquare size={17} aria-hidden="true" className="panel-mark" />} />
        <div className="agent-controls">
          <label className="field-label" htmlFor="fixture">Fixture</label>
          <div className="select-wrap"><select id="fixture" className="select-input" value={fixtureId} onChange={(event) => setFixtureId(event.target.value)} disabled={fixtures.status !== 'success' || (fixtures.data ?? []).length === 0}><option value="">{fixtures.status === 'loading' ? 'Loading fixtures…' : fixtures.data?.length ? 'Choose a fixture' : 'No fixtures available'}</option>{(fixtures.data ?? []).map((fixture) => <option key={fixture} value={fixture}>{fixture}</option>)}</select><ChevronDown size={15} aria-hidden="true" /></div>
          <label className="field-label" htmlFor="agent-task">Task</label>
          <input id="agent-task" className="text-input" value={task} onChange={(event) => setTask(event.target.value)} placeholder="Describe the agent task" />
          <div className="mode-toggle" role="group" aria-label="Agent execution mode">
            <button type="button" className={mode === 'protected' ? 'mode-active' : ''} onClick={() => setMode('protected')}><LockKeyhole size={14} aria-hidden="true" />Protected</button>
            <button type="button" className={mode === 'unprotected' ? 'mode-active' : ''} onClick={() => setMode('unprotected')}><ArrowUpRight size={14} aria-hidden="true" />Unprotected</button>
          </div>
          <button className="button button-secondary agent-run-button" type="button" onClick={() => void onAgentRun(mode)} disabled={!fixtureId || agentLoading !== null}><Play size={15} fill="currentColor" aria-hidden="true" />{agentLoading === mode ? 'Running…' : `Run ${mode}`}</button>
          {agentError && <div className="inline-error"><AlertCircle size={14} aria-hidden="true" />{agentError}</div>}
        </div>
        <AgentResult mode={mode} run={activeRun} events={sessionEvents} />
      </section>

      <DemoCompare runs={runs} onRun={onAgentRun} loading={agentLoading} fixtureReady={Boolean(fixtureId)} />

      <section className="panel panel-audit grid-span-7">
        <PanelHeader eyebrow="RECENT AUDIT" title="Decision stream" description="Persisted events from the gateway boundary." action={<button type="button" className="text-button" onClick={() => onOpenSection('audit')}>Open stream <ArrowUpRight size={13} aria-hidden="true" /></button>} />
        {audit.status === 'loading' && !audit.data ? <LoadingState label="Reading audit stream" /> : audit.error ? <ErrorState message={audit.error} onRetry={onRetryAudit} /> : auditItemsPreview(audit.data ?? [], onOpenAudit)}
      </section>

      <section className="panel panel-approvals grid-span-5">
        <PanelHeader eyebrow="HUMAN GATE" title="Approval queue" description="Operator decisions for actions that need a second look." action={<button type="button" className="text-button" onClick={() => onOpenSection('approvals')}>View all <ArrowUpRight size={13} aria-hidden="true" /></button>} />
        <ApprovalList items={pendingApprovals.slice(0, 3)} onDecision={onDecision} actionId={approvalAction} compact />
      </section>

      <section className="panel panel-benchmark grid-span-12">
        <PanelHeader eyebrow="EVALUATION LAB" title="Benchmark report" description="Latest persisted run across the backend's benchmark corpus." action={<div className="panel-actions"><button type="button" className="text-button" onClick={() => onOpenSection('bench')}>Open report <ArrowUpRight size={13} aria-hidden="true" /></button><button type="button" className="button button-quiet" onClick={onRunBenchmark} disabled={benchmarkRunning}>{benchmarkRunning ? <Loader2 size={14} className="spin" aria-hidden="true" /> : <RefreshCw size={14} aria-hidden="true" />}Run benchmark</button></div>} />
        <BenchmarkSummary state={benchmark} onRetry={onRetryBenchmark} />
      </section>

      {firstError && <div className="data-footnote grid-span-12"><AlertCircle size={14} aria-hidden="true" />Some panels are waiting on the API. Existing telemetry remains visible where available.</div>}
    </div>
  );
}

function Pipeline({ scan }: { scan: ScanResult }) {
  const latency = scan.stage_latency ?? scan.stage_latencies ?? scan.latency ?? {};
  const total = Number(latency.total_ms ?? latency.total ?? 0);
  const stageValues = stageNames.map((stage) => {
    const candidates = [stage, `${stage}_ms`, `${stage}Ms`];
    const key = candidates.find((candidate) => typeof latency[candidate] === 'number');
    return { name: stage, value: key ? latency[key] : undefined };
  });
  const hasValues = stageValues.some((stage) => stage.value !== undefined) || Object.keys(latency).length > 0;
  if (!hasValues) return <EmptyState label="No stage latency fields" detail="The API returned a scan without pipeline timing." />;
  return (
    <div className="pipeline-wrap">
      <div className="pipeline-total"><span>Total path</span><strong>{formatMetric(total, ' ms')}</strong></div>
      <div className="pipeline-planes">
        {stageValues.map((stage, index) => <div className="pipeline-plane" key={stage.name} style={{ '--plane-depth': `${index * 10}px` } as React.CSSProperties}><div className="plane-cap"><span>{titleCase(stage.name)}</span><strong>{formatMetric(stage.value, ' ms')}</strong></div><div className="plane-fill" /></div>)}
      </div>
      <div className="pipeline-foot"><span><span className="pipeline-line pipeline-line-cyan" />Deterministic rule path</span><span><span className="pipeline-line pipeline-line-muted" />Response fields: {Object.keys(latency).length ? 'available' : 'empty'}</span></div>
    </div>
  );
}

function AgentResult({ mode, run, events }: { mode: RunMode; run?: RunState; events: AgentEvent[] }) {
  if (!run) return <EmptyState label="No run in this mode" detail="Choose a fixture and start the agent lab." />;
  const response = run.response;
  const decision = response.tool_decision;
  const eventCount = run.events.length;
  return (
    <div className="agent-result">
      <div className="result-topline"><span className="result-session">{response.session_id}</span><VerdictBadge value={response.status} compact /></div>
      <div className="result-grid"><div><span className="metric-label">Fixture</span><strong>{response.fixture_id}</strong></div><div><span className="metric-label">Tool action</span><strong>{decision?.action ? titleCase(decision.action) : '—'}</strong></div><div><span className="metric-label">Stream</span><strong>{formatMetric(eventCount)} events</strong></div></div>
      {decision?.reason && <p className="result-reason">{decision.reason}</p>}
      {response.outbox_id && <div className="outbox-note"><FileCheck2 size={14} aria-hidden="true" /><span>Local outbox write: <code>{response.outbox_id}</code></span></div>}
    </div>
  );
}

function DemoCompare({ runs, onRun, loading, fixtureReady }: { runs: Partial<Record<RunMode, RunState>>; onRun: (mode?: RunMode) => void; loading: RunMode | null; fixtureReady: boolean }) {
  const cards: RunMode[] = ['protected', 'unprotected'];
  return (
    <section className="panel demo-compare grid-span-12">
      <div className="compare-heading"><div><p className="eyebrow">CONTROLLED COMPARISON</p><h2 className="panel-title">Same input. Different boundary.</h2><p className="panel-description">The unprotected lane is a local demonstration of what the policy gate prevents.</p></div><div className="compare-legend"><span><span className="legend-bar legend-protected" />protected</span><span><span className="legend-bar legend-unprotected" />unprotected</span></div></div>
      <div className="compare-grid">
        {cards.map((cardMode) => {
          const run = runs[cardMode];
          return <div className={`compare-card compare-${cardMode}`} key={cardMode}><div className="compare-card-head"><div><span className="mode-kicker">{cardMode === 'protected' ? <LockKeyhole size={14} aria-hidden="true" /> : <ArrowUpRight size={14} aria-hidden="true" />}{cardMode}</span><span className="compare-caption">{cardMode === 'protected' ? 'policy enforced' : 'policy bypassed'}</span></div>{run && <VerdictBadge value={run.response.status} compact />}</div>{run ? <><div className="compare-outcome"><strong>{run.response.status === 'completed' ? 'Action reached local outbox' : titleCase(run.response.status)}</strong><span>{run.response.tool_decision?.reason || 'No tool decision returned.'}</span></div>{run.response.scan_result && <div className="compare-meta"><span>Risk {formatMetric(run.response.scan_result.risk)}</span><span>{run.response.scan_result.signals.length} signals</span></div>}</> : <EmptyState label="No comparison run" detail="Run this lane to record the API response." />}<button type="button" className="button button-quiet compare-run" onClick={() => void onRun(cardMode)} disabled={!fixtureReady || loading !== null}>{loading === cardMode ? <Loader2 size={14} className="spin" aria-hidden="true" /> : <Play size={14} fill="currentColor" aria-hidden="true" />}{loading === cardMode ? 'Running…' : `Run ${cardMode}`}</button></div>;
        })}
      </div>
    </section>
  );
}

function auditItemsPreview(items: AuditItem[], onOpen: (item: AuditItem) => void) {
  if (items.length === 0) return <EmptyState label="Audit stream is empty" detail="A scan or agent run will create the first event." />;
  return <div className="audit-list">{items.slice(-5).reverse().map((item) => <button type="button" className="audit-row" key={item.event_id} onClick={() => onOpen(item)}><span className="audit-event-icon"><EventIcon type={item.event_type} /></span><span className="audit-row-copy"><strong>{titleCase(item.action || item.event_type)}</strong><small>{item.source} · {formatTime(item.created_at)}</small></span><span className="audit-risk">{formatMetric(item.risk_score)}</span><VerdictBadge value={item.decision} compact /><ChevronRight size={14} aria-hidden="true" /></button>)}</div>;
}

function EventIcon({ type }: { type: string }) {
  if (type.includes('scan')) return <Search size={14} aria-hidden="true" />;
  if (type.includes('tool')) return <TerminalSquare size={14} aria-hidden="true" />;
  if (type.includes('approval')) return <ClipboardCheck size={14} aria-hidden="true" />;
  return <Activity size={14} aria-hidden="true" />;
}

function AuditSection({ items, state, onRetry, onOpen }: { items: AuditItem[]; state: ResourceState<AuditItem[]>; onRetry: () => void; onOpen: (item: AuditItem) => void }) {
  return <section className="section-stack"><div className="section-title-row"><div><p className="eyebrow">TELEMETRY / PERSISTED</p><h2>Audit stream</h2><p>Every scan, tool decision, and approval boundary recorded by the gateway.</p></div><span className="section-chip"><Activity size={14} aria-hidden="true" />{state.data ? `${state.data.length} loaded` : 'awaiting data'}</span></div><div className="panel panel-full">{state.status === 'loading' && !state.data ? <LoadingState label="Reading audit stream" /> : state.error ? <ErrorState message={state.error} onRetry={onRetry} /> : items.length === 0 ? <EmptyState label="No persisted events" detail="The backend will expose events after the first request." /> : <div className="audit-table">{items.slice().reverse().map((item) => <button type="button" className="audit-table-row" key={item.event_id} onClick={() => onOpen(item)}><span className="audit-event-icon"><EventIcon type={item.event_type} /></span><span className="audit-table-main"><strong>{titleCase(item.action || item.event_type)}</strong><small>{item.event_id}</small></span><span className="audit-table-source">{item.source}</span><span className="audit-table-time">{formatDate(item.created_at)}</span><span className="audit-risk">{formatMetric(item.risk_score)}</span><VerdictBadge value={item.decision} compact /><ChevronRight size={14} aria-hidden="true" /></button>)}</div>}</div></section>;
}

function PoliciesSection({ state, policy, onRetry, onRuleAction, onChange, onSave, saving, message }: { state: ResourceState<PolicyDocument>; policy: PolicyDocument | null; onRetry: () => void; onRuleAction: (ruleId: string, action: string) => void; onChange: (policy: PolicyDocument | null) => void; onSave: () => void; saving: boolean; message: string | null }) {
  const rules = Object.entries(policy?.rule_actions ?? {});
  const toolPolicies = Object.entries(policy?.tool_policies ?? {});
  return <section className="section-stack"><div className="section-title-row"><div><p className="eyebrow">POLICY / DECLARATIVE</p><h2>Policy rules</h2><p>Hot-reload the active decision surface without leaving the control center.</p></div><button type="button" className="button button-primary" onClick={onSave} disabled={!policy || saving}>{saving ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <Check size={15} aria-hidden="true" />}{saving ? 'Saving…' : 'Save policy'}</button></div>{message && <div className={`save-message ${message.toLowerCase().includes('error') || message.toLowerCase().includes('failed') ? 'save-message-error' : ''}`} role="status"><CheckCircle2 size={15} aria-hidden="true" />{message}</div>}<div className="policy-layout"><div className="panel panel-full">{state.status === 'loading' && !state.data ? <LoadingState label="Reading policy document" /> : state.error ? <ErrorState message={state.error} onRetry={onRetry} /> : !policy ? <EmptyState label="No policy document" detail="The backend did not return the active policy." /> : <><PanelHeader eyebrow="RULE ACTIONS" title={policy.name ?? 'Default policy'} description={policy.description} /><div className="rule-list">{rules.length === 0 ? <EmptyState label="No rule actions returned" /> : rules.map(([ruleId, action]) => <div className="rule-row" key={ruleId}><span className="rule-icon"><KeyRound size={14} aria-hidden="true" /></span><span className="rule-copy"><strong>{ruleId}</strong><small>Decision for matching content</small></span><div className="select-wrap rule-select"><select aria-label={`Action for ${ruleId}`} className="select-input" value={action} onChange={(event) => onRuleAction(ruleId, event.target.value)}><option value="allow">Allow</option><option value="review">Review</option><option value="deny">Deny</option></select><ChevronDown size={14} aria-hidden="true" /></div></div>)}</div></>}</div><div className="policy-side"><div className="panel panel-full"><PanelHeader eyebrow="THRESHOLDS" title="Risk boundaries" /><div className="threshold-grid"><ThresholdInput label="Review at" value={policy?.thresholds?.review} onChange={(value) => onChange(policy ? { ...policy, thresholds: { ...(policy.thresholds ?? {}), review: value } } : policy)} /><ThresholdInput label="Deny at" value={policy?.thresholds?.deny} onChange={(value) => onChange(policy ? { ...policy, thresholds: { ...(policy.thresholds ?? {}), deny: value } } : policy)} /></div></div><div className="panel panel-full"><PanelHeader eyebrow="TOOL SURFACE" title="Guarded tools" /><div className="tool-policy-list">{toolPolicies.length === 0 ? <EmptyState label="No tool policies returned" /> : toolPolicies.map(([name, config]) => <div className="tool-policy-row" key={name}><span className="tool-policy-icon"><TerminalSquare size={14} aria-hidden="true" /></span><span><strong>{name}</strong><small>{Object.keys(config).length} controls exposed by API</small></span><StatusDot tone="allow" /></div>)}</div></div></div></div></section>;
}

function ThresholdInput({ label, value, onChange }: { label: string; value?: number; onChange: (value: number) => void }) {
  return <label className="threshold-field"><span>{label}</span><input className="number-input" type="number" min="0" max="100" value={value ?? ''} onChange={(event) => onChange(event.target.value === '' ? 0 : Number(event.target.value))} /><small>Risk boundary from policy</small></label>;
}

function ApprovalsSection({ state, items, pending, onRetry, onDecision, actionId }: { state: ResourceState<Approval[]>; items: Approval[]; pending: Approval[]; onRetry: () => void; onDecision: (approval: Approval, decision: 'approve' | 'deny') => void; actionId: string | null }) {
  return <section className="section-stack"><div className="section-title-row"><div><p className="eyebrow">HUMAN GATE / ACTION REQUIRED</p><h2>Approvals</h2><p>Resolve tool actions that crossed the declarative policy boundary.</p></div><span className="section-chip"><ClipboardCheck size={14} aria-hidden="true" />{pending.length} pending</span></div><div className="panel panel-full">{state.status === 'loading' && !state.data ? <LoadingState label="Reading approvals" /> : state.error ? <ErrorState message={state.error} onRetry={onRetry} /> : items.length === 0 ? <EmptyState label="Approval queue is empty" detail="Approval requests will appear when policy asks for an operator." /> : <div className="approval-full-list"><ApprovalList items={items} onDecision={onDecision} actionId={actionId} /></div>}</div></section>;
}

function ApprovalCountdown({ approvalId, onExpire }: { approvalId: string; onExpire: () => void }) {
  const [seconds, setSeconds] = React.useState(60);
  const expireRef = React.useRef(onExpire);
  expireRef.current = onExpire;

  React.useEffect(() => {
    setSeconds(60);
    const timer = window.setInterval(() => {
      setSeconds((current) => {
        if (current <= 1) {
          window.clearInterval(timer);
          expireRef.current();
          return 0;
        }
        return current - 1;
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [approvalId]);

  const circumference = 2 * Math.PI * 15;
  const offset = circumference * (1 - seconds / 60);
  return (
    <span className="approval-countdown" aria-label={`${seconds} seconds until this approval auto-denies`}>
      <svg viewBox="0 0 36 36" role="img" aria-hidden="true">
        <circle className="countdown-track" cx="18" cy="18" r="15" />
        <circle className="countdown-value" cx="18" cy="18" r="15" style={{ strokeDasharray: circumference, strokeDashoffset: offset }} />
      </svg>
      <span>{seconds}s</span>
    </span>
  );
}

function ApprovalList({ items, onDecision, actionId, compact = false }: { items: Approval[]; onDecision: (approval: Approval, decision: 'approve' | 'deny') => void; actionId: string | null; compact?: boolean }) {
  if (items.length === 0) return <EmptyState label="No pending approvals" detail="The queue is clear." />;
  return <div className={`approval-list ${compact ? 'approval-list-compact' : ''}`}>{items.map((approval) => <div className="approval-row" key={approval.approval_id}><div className="approval-icon"><Bell size={15} aria-hidden="true" /></div><div className="approval-copy"><div className="approval-heading"><strong>{approval.reason || 'Operator decision requested'}</strong><VerdictBadge value={approval.status} compact /></div><small>{approval.requested_by} · {formatDate(approval.requested_at)}</small><code>{approval.approval_id}</code></div>{approval.status === 'pending' ? <><ApprovalCountdown approvalId={approval.approval_id} onExpire={() => onDecision(approval, 'deny')} /><div className="approval-actions"><button className="button button-quiet button-allow" type="button" onClick={() => onDecision(approval, 'approve')} disabled={actionId !== null}>{actionId === `${approval.approval_id}:approve` ? <Loader2 size={13} className="spin" aria-hidden="true" /> : <Check size={13} aria-hidden="true" />}Approve</button><button className="button button-quiet button-deny" type="button" onClick={() => onDecision(approval, 'deny')} disabled={actionId !== null}>{actionId === `${approval.approval_id}:deny` ? <Loader2 size={13} className="spin" aria-hidden="true" /> : <X size={13} aria-hidden="true" />}Deny</button></div></> : <span className="approval-resolved">{titleCase(approval.status)}</span>}</div>)}</div>;
}

function BenchmarkSection({ state, onRetry, onRun, running }: { state: ResourceState<BenchmarkLatest>; onRetry: () => void; onRun: () => void; running: boolean }) {
  const metrics = state.data?.metrics ?? null;
  return <section className="section-stack"><div className="section-title-row"><div><p className="eyebrow">EVALUATION LAB / OFFLINE</p><h2>Benchmark report</h2><p>Measure deterministic coverage and latency against the persisted benchmark run.</p></div><button type="button" className="button button-primary" onClick={onRun} disabled={running}>{running ? <Loader2 size={15} className="spin" aria-hidden="true" /> : <RefreshCw size={15} aria-hidden="true" />}{running ? 'Running…' : 'Run benchmark'}</button></div><div className="panel panel-full">{state.status === 'loading' && !state.data ? <LoadingState label="Reading benchmark report" /> : state.error ? <ErrorState message={state.error} onRetry={onRetry} /> : !metrics ? <EmptyState label="No benchmark run persisted" detail="Run the backend benchmark to populate this report." /> : <BenchmarkReport metrics={metrics} run={state.data} />}</div></section>;
}

function BenchmarkSummary({ state, onRetry }: { state: ResourceState<BenchmarkLatest>; onRetry: () => void }) {
  const metrics = state.data?.metrics;
  if (state.status === 'loading' && !state.data) return <LoadingState label="Reading benchmark report" />;
  if (state.error) return <ErrorState message={state.error} onRetry={onRetry} />;
  if (!metrics) return <EmptyState label="No benchmark run persisted" detail="Run the benchmark to see coverage and technique recall." />;
  return <BenchmarkReport metrics={metrics} run={state.data} compact />;
}

function BenchmarkReport({ metrics, run, compact = false }: { metrics: BenchmarkMetrics; run: BenchmarkLatest | null; compact?: boolean }) {
  const techniques = Object.entries(metrics.per_category_recall ?? {});
  return <div className={`benchmark-report ${compact ? 'benchmark-report-compact' : ''}`}><div className="benchmark-metrics"><div className="benchmark-stat"><span>Precision</span><strong>{formatPercent(metrics.precision)}</strong></div><div className="benchmark-stat"><span>Recall</span><strong>{formatPercent(metrics.recall)}</strong></div><div className="benchmark-stat"><span>False positive rate</span><strong>{formatPercent(metrics.fpr)}</strong></div><div className="benchmark-stat"><span>P95 latency</span><strong>{formatMetric(metrics.p95_latency_ms, ' ms')}</strong></div><div className="benchmark-stat"><span>Tokens / scan</span><strong>{formatMetric(metrics.tokens_per_scan)}</strong></div></div><div className="technique-panel"><div className="technique-head"><span className="metric-label">Technique recall</span><span className="run-id">{run?.run_id ?? 'run unavailable'} · {formatDate(run?.created_at)}</span></div>{techniques.length === 0 ? <EmptyState label="No category recall returned" /> : <div className="technique-bars">{techniques.map(([name, value]) => <div className="technique-row" key={name}><span>{titleCase(name)}</span><div className="bar-track"><span className="bar-fill" style={{ width: `${Math.max(0, Math.min(100, value * 100))}%` }} /></div><strong>{formatPercent(value)}</strong></div>)}</div>}</div></div>;
}

function CommandDialog({ query, setQuery, actions, inputRef, onClose }: { query: string; setQuery: (value: string) => void; actions: Array<{ id: string; label: string; detail: string; icon: typeof Search; run: () => void }>; inputRef: React.RefObject<HTMLInputElement>; onClose: () => void }) {
  const reduceMotion = useReducedMotion();
  return <motion.div className="modal-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.16 }} onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><motion.div className="command-dialog" role="dialog" aria-modal="true" aria-label="Command bar" initial={{ opacity: 0, y: -12, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -8, scale: 0.98 }} transition={{ duration: reduceMotion ? 0 : 0.16 }}><div className="command-search"><Search size={18} aria-hidden="true" /><input ref={inputRef} value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search actions…" onKeyDown={(event) => { if (event.key === 'Escape') onClose(); if (event.key === 'Enter' && actions[0]) actions[0].run(); }} /><kbd>ESC</kbd></div><div className="command-list">{actions.length === 0 ? <EmptyState label="No matching actions" /> : actions.map(({ id, label, detail, icon: Icon, run }) => <button type="button" className="command-item" key={id} onClick={run}><span className="command-icon"><Icon size={16} aria-hidden="true" /></span><span><strong>{label}</strong><small>{detail}</small></span><ChevronRight size={14} aria-hidden="true" /></button>)}</div><div className="command-footer"><span><kbd>↵</kbd> run action</span><span><kbd>ESC</kbd> close</span></div></motion.div></motion.div>;
}

function AuditSheet({ item, detail, loading, onClose }: { item: AuditItem; detail: Record<string, unknown> | null; loading: boolean; onClose: () => void }) {
  const reduceMotion = useReducedMotion();
  const data = detail ?? item as unknown as Record<string, unknown>;
  return <motion.div className="sheet-backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: reduceMotion ? 0 : 0.16 }} onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}><motion.aside className="audit-sheet" role="dialog" aria-modal="true" aria-label="Audit event detail" initial={{ x: '100%' }} animate={{ x: 0 }} exit={{ x: '100%' }} transition={reduceMotion ? { duration: 0 } : { type: 'spring', stiffness: 330, damping: 34 }}><div className="sheet-header"><div><p className="eyebrow">AUDIT EVENT</p><h2>{titleCase(item.action || item.event_type)}</h2></div><button className="icon-button" type="button" aria-label="Close audit detail" onClick={onClose}><X size={18} aria-hidden="true" /></button></div><div className="sheet-verdict"><VerdictBadge value={item.decision} /><span>{formatDate(item.created_at)}</span></div>{loading ? <LoadingState label="Loading event detail" /> : <div className="sheet-content"><div className="detail-grid"><div><span className="metric-label">Event ID</span><code>{item.event_id}</code></div><div><span className="metric-label">Risk score</span><strong>{formatMetric(item.risk_score)}</strong></div><div><span className="metric-label">Source</span><strong>{item.source}</strong></div><div><span className="metric-label">Policy</span><strong>{item.policy}</strong></div></div><div className="detail-block"><span className="metric-label">Matched rules</span><pre>{JSON.stringify(data.matched_rules ?? data.matched_rules_json ?? [], null, 2)}</pre></div><div className="detail-block"><span className="metric-label">Payload</span><pre>{JSON.stringify(data.payload ?? data.payload_json ?? {}, null, 2)}</pre></div><div className="detail-block"><span className="metric-label">Provenance</span><pre>{JSON.stringify(data.provenance ?? data.provenance_json ?? [], null, 2)}</pre></div></div>}</motion.aside></motion.div>;
}

export default App;
