// Shared TypeScript interfaces matching backend API schemas

export type TargetType = 'rest' | 'browser';
export type ScanMode = 'single' | 'multiturn' | 'converter';
export type ScanStatus = 'pending' | 'running' | 'done' | 'error';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface ScanRequest {
  target_type: TargetType;
  target_url: string;

  // REST fields
  body_template?: string;
  response_field?: string;
  auth_header?: string;

  // Browser fields
  input_selector?: string;
  send_button_selector?: string;
  response_selector?: string;
  wait_for_response_timeout?: number;
  login_config?: Record<string, string>;

  // Attack orchestration settings
  packs?: string[];
  scan_mode: ScanMode;
  max_turns: number;
  converters?: string[];
  use_llm_judge: boolean;
  judge_model: string;
  ollama_url: string;
  delay: number;
  concurrency: number;
  limit?: number;
}

export interface BrowserTestSelectorsRequest {
  target_url: string;
  input_selector: string;
  send_button_selector?: string;
  response_selector?: string;
  wait_for_response_timeout?: number;
  login_config?: Record<string, string>;
}

export interface SelectorTestResult {
  selector: string;
  found: boolean;
  visible?: boolean;
  count?: number;
  note?: string;
  error?: string;
}

export interface BrowserTestSelectorsResponse {
  ok: boolean;
  url: string;
  selectors: Record<string, SelectorTestResult>;
  error?: string;
}

export interface SeverityCounts {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
}

export interface ScanSummary {
  scan_id: string;
  status: ScanStatus;
  target_type: TargetType;
  scan_mode: ScanMode;
  target_url: string;
  start_time?: string;
  end_time?: string;
  progress: number;
  total: number;
  vulnerable_count: number;
  total_payloads: number;
  posture_score?: number;
  grade?: string;
  circuit_broken: boolean;
  error_message?: string;
  severity_counts: Record<string, number>;
  likert_distribution: Record<string, number>;
  category_scores: Record<string, number>;
  duration_seconds?: number;
  total_target_tokens?: number;
  total_judge_tokens?: number;
  total_tokens?: number;
  judge_tokens_saved?: number;
}

export interface ConversationTurn {
  turn_number: number;
  role: 'attacker' | 'target';
  content: string;
  timestamp: number;
  prompt_tokens?: number;
  completion_tokens?: number;
}

export interface Finding {
  payload_id: string;
  category: string;
  owasp_id: string;
  prompt: string;
  sent_prompt?: string;
  response_text: string;
  vulnerable: boolean;
  severity: string;
  confidence: number;
  judge_type: string;
  reasoning: string;
  error?: string;
  converter_used?: string;
  original_prompt?: string;
  likert_score: number;
  target_prompt_tokens?: number;
  target_completion_tokens?: number;
  judge_prompt_tokens?: number;
  judge_completion_tokens?: number;
  total_tokens?: number;
  // Multi-turn extras
  succeeded_at_turn?: number;
  full_transcript?: ConversationTurn[];
  attack_strategy?: string;
  breached_vulnerabilities?: string[];
  breach_factors?: string[];
}

export interface PayloadPackInfo {
  name: string;
  category: string;
  owasp_id: string;
  count: number;
  file_path: string;
  sample_payload?: {
    id: string;
    category: string;
    owasp_id: string;
    severity: string;
    prompt: string;
    requires_llm_judge: boolean;
  };
  source?: string;
  is_community?: boolean;
}

export interface CommunityPreviewResponse {
  detected_format: 'csv' | 'json' | 'txt';
  columns?: string[];
  sample_rows: Record<string, unknown>[];
  total_count: number;
  suggested_mapping: Record<string, string>;
  raw_text?: string;
}

export interface CommunityConvertResponse {
  yaml_content: string;
  total_count: number;
}

export interface CommunitySaveResponse {
  status: string;
  pack_name: string;
  output_path: string;
  count: number;
  message: string;
}

export interface EvalMetrics {
  total_samples: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
}

export interface EvalJudgeResponse {
  status: string;
  summary: EvalMetrics;
  benchmarks: Record<string, { accuracy: number; correct: number; total: number }>;
  report_path: string;
}

// SSE event types from the server
export interface SSEEvent {
  event: string;
  data: Record<string, unknown>;
}
