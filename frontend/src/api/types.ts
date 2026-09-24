// Mirrors the FastAPI schemas (src/data/schemas, src/utils/review.py).

export type ReviewStatus = "pending" | "running" | "completed" | "failed";
export type Severity = "Critical" | "High" | "Medium" | "Low";
export type KpiStatus = "open" | "partially_open" | "closed" | "not_applicable" | "not_verified";
export type StageStatus = "running" | "completed" | "failed";

export interface User {
  id: string;
  email: string;
  is_active: boolean;
  created_at: string;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_at: string;
}

export interface AuthResponse {
  user: User;
  token: TokenPair;
}

export interface IssuesSummary {
  total: number;
  by_severity: Partial<Record<Severity, number>>;
  by_category: Record<string, number>;
  security_kpis: Record<string, KpiStatus>;
}

export interface StageProgress {
  status: StageStatus;
  started_at?: string;
  finished_at?: string;
}

export interface AgentProgress {
  status: "running" | "completed" | "incomplete" | "timed_out" | "failed" | "skipped";
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
  model_calls?: number;
}

export interface Progress {
  stages?: Record<string, StageProgress>;
  agents?: Record<string, AgentProgress>;
}

export interface ReviewRead {
  id: string;
  repository_id: string;
  commit_sha: string | null;
  branch: string | null;
  status: ReviewStatus;
  stage: string | null;
  progress: Progress | null;
  issues_summary: IssuesSummary | null;
  engine_version: string | null;
  provider: string | null;
  model: string | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface ReviewListItem extends ReviewRead {
  repository_name: string;
}

export interface ReviewDetail extends ReviewRead {
  report_markdown: string | null;
  report_data: DeepReviewReport | null;
}

export interface RepositorySummary {
  id: string;
  name: string;
  clone_url: string;
  head_sha: string | null;
  default_branch: string | null;
  source_type: string | null;
  created_at: string;
  review_count: number;
  latest_review: ReviewRead | null;
}

export interface IngestionAccepted {
  repository_id: string;
  review_report_id: string;
  status: ReviewStatus;
}

// ---- DeepReviewReport (report_data) -------------------------------------

export interface EvidenceRef {
  file: string;
  line_start: number;
  line_end: number | null;
  note: string | null;
}

export interface Verification {
  verdict: "confirmed" | "rejected" | "adjusted";
  original_severity: Severity;
  note: string;
}

export interface Finding {
  id: string;
  category_id: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  title: string;
  description: string;
  impact: string;
  remediation: string | null;
  evidence: EvidenceRef[];
  kpi_ids: string[];
  static_finding_ids: string[];
  verification: Verification | null;
}

export interface ReviewCategory {
  id: string;
  title: string;
  code: string;
  owns_security_kpis: boolean;
}

export interface KpiAssessment {
  kpi_id: string;
  title: string;
  status: KpiStatus;
  summary: string;
  evidence: EvidenceRef[];
  finding_ids: string[];
}

export interface StaticToolSummary {
  tool: string;
  status: string;
  total: number;
  true_positive: number;
  false_positive: number;
  low_value: number;
  untriaged: number;
}

export interface StaticTriage {
  finding_id: string;
  tool: string;
  verdict: "true_positive" | "false_positive" | "low_value";
  reason: string;
  triaged_by: string;
}

export interface PriorityItem {
  title: string;
  rationale: string;
  finding_ids: string[];
}

export interface RootCause {
  title: string;
  explanation: string;
  finding_ids: string[];
}

export interface AgentRun {
  agent: string;
  status: AgentProgress["status"];
  duration_seconds: number;
  model_calls: number;
  input_tokens: number;
  output_tokens: number;
  error: string | null;
}

export interface ReviewStatistics {
  duration_seconds: number;
  findings_recorded: number;
  findings_reported: number;
  findings_rejected_by_verifier: number;
  findings_rejected_invalid_evidence: number;
  findings_merged_as_duplicates: number;
  findings_dropped_low_confidence: number;
  static_findings_total: number;
  static_findings_triaged: number;
  static_false_positives: number;
  input_tokens: number;
  output_tokens: number;
}

export interface DeepReviewReport {
  engine_version: string;
  repository_id: string;
  repository_name: string;
  head_sha: string;
  provider: string;
  model: string;
  generated_at: string;
  summary: {
    scope: string;
    verdict: string;
    priority_order: PriorityItem[];
    cross_cutting: RootCause[];
    verification_note: string;
  };
  categories: ReviewCategory[];
  findings: Finding[];
  rejected_findings: Finding[];
  kpi_assessments: KpiAssessment[];
  static_triage: StaticTriage[];
  static_summary: StaticToolSummary[];
  agent_runs: AgentRun[];
  statistics: ReviewStatistics;
}
