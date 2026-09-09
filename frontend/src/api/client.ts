/**
 * api/client.ts - Type-safe API client for FastAPI backend
 */

export interface ServiceHealth {
  status: 'online' | 'connected' | 'degraded' | 'unreachable' | 'unauthorized';
  uptime_seconds?: number;
  database?: boolean | string;
  provider?: string;
  base_url?: string;
  active_model?: string;
  available_models?: string[];
  server_name?: string;
  version?: string;
  latency_ms?: number;
  error?: string;
}

export interface HealthResponse {
  timestamp: string;
  services: {
    fastapi: ServiceHealth;
    llm: ServiceHealth;
    splunk: ServiceHealth;
  };
}

export interface FrequencyInfo {
  event_count: number;
  time_window_value: number;
  time_window_unit: string;
  raw_frequency: string;
}

export interface ConditionClause {
  field_name: string;
  operator: string;
  value: string;
  is_negated: boolean;
  raw_clause: string;
}

export interface ParsedArcSightRule {
  rule_name: string;
  priority: number;
  severity: string;
  frequency: FrequencyInfo;
  group_by_fields: string[];
  mitre_tactic: string | null;
  mitre_source: 'extracted from rule' | 'missing';
  mitre_uri: string | null;
  raw_condition: string;
  clauses: ConditionClause[];
  required_terms: string[];
  exclusion_terms: string[];
  referenced_fields: string[];
}

export interface SingleLanguageValidation {
  target_language: string;
  passed: boolean;
  coverage_pct: number;
  required_terms_checked: string[];
  missing_required: string[];
  exclusion_terms_checked: string[];
  missing_exclusions: string[];
  wrongly_included_as_match: string[];
  notes: string[];
}

export interface ValidationBundle {
  kql: SingleLanguageValidation;
  spl: SingleLanguageValidation;
  passed: boolean;
  overall_coverage_pct: number;
}

export interface TranslateDirectResponse {
  success: boolean;
  parsed_rule: ParsedArcSightRule;
  kql_query: string;
  spl_query: string;
  validation: ValidationBundle;
  raw_llm_output: string;
  deep_mode?: boolean;
  deep_mode_passed?: boolean;
  deep_mode_attempts?: number;
  deep_mode_failed?: boolean;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface ThreatAnalysis {
  threat_summary: string;
  mitre_techniques: MitreTechnique[];
  detection_review: {
    false_positive_sources: string[];
    evasion_blindspots: string[];
    time_window_evaluation: string;
    missing_triage_fields: string[];
  };
  analyst_triage_guide: {
    triage_priority: string;
    initial_questions: string[];
    containment_steps: string[];
    escalation_criteria: string[];
  };
  rule_naming_suggestions: string[];
}

export interface MdeCoverageInput {
  verdict: string;
  notes: string;
  reviewer_name?: string;
}

export interface SaveRunbookRequest {
  rule_name: string;
  severity: string;
  priority: number;
  mitre_tactic?: string | null;
  mitre_source: string;
  mitre_uri?: string | null;
  frequency_str: string;
  group_by: string[];
  kql_query: string;
  kql_validation: SingleLanguageValidation;
  spl_query: string;
  spl_validation: SingleLanguageValidation;
  threat_analysis: ThreatAnalysis;
  mde_coverage: MdeCoverageInput;
  llm_model?: string;
}

export interface SaveRunbookResponse {
  success: boolean;
  filename: string;
  file_path: string;
  content: string;
  message: string;
}

export interface LiveSplunkTestResponse {
  success: boolean;
  query: string;
  hit_count: number;
  sample_events: Record<string, any>[];
  error?: string;
}

export interface AuditLogItem {
  id: number;
  timestamp: string;
  rule_name: string;
  endpoint: string;
  provider?: string;
  model?: string;
  outcome: string;
  coverage_pct?: number;
  details: Record<string, any>;
}

export interface AuditLogResponse {
  history: AuditLogItem[];
  stats: {
    total_events: number;
    passed_count: number;
    failed_count: number;
    average_coverage_pct: number;
  };
}

export interface LLMConfig {
  provider: string;
  model_name?: string;
  custom_base_url?: string;
  api_key?: string;
}

const API_BASE = '/api';

export async function fetchHealth(
  provider = 'lm_studio',
  customBaseUrl?: string,
  apiKey?: string
): Promise<HealthResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  const cleanKey = (apiKey || '').trim();
  if (cleanKey) {
    headers['Authorization'] = `Bearer ${cleanKey}`;
  }

  const res = await fetch(`${API_BASE}/health`, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      provider,
      custom_base_url: customBaseUrl || null,
      api_key: cleanKey || null,
    }),
  });

  if (!res.ok) {
    throw new Error(`Health check failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function translateDirect(
  rawText: string,
  llmConfig: LLMConfig,
  deepMode = false,
  onStatus?: (status: string) => void
): Promise<TranslateDirectResponse> {
  const res = await fetch(`${API_BASE}/translate-direct`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: deepMode ? 'text/event-stream, application/json' : 'application/json',
    },
    body: JSON.stringify({
      raw_text: rawText,
      llm_config: llmConfig,
      deep_mode: deepMode,
    }),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Translation failed with status ${res.status}`);
  }

  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('text/event-stream') && res.body) {
    const reader = res.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';
    let finalResult: TranslateDirectResponse | null = null;

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data:')) continue;

        const dataStr = trimmed.replace(/^data:\s*/, '');
        try {
          const parsed = JSON.parse(dataStr);
          if (parsed.error) {
            throw new Error(parsed.error);
          }
          if (parsed.result) {
            if (onStatus) {
              onStatus('> Translation Complete!');
            }
            finalResult = parsed.result;
          } else if (parsed.kql_query && parsed.spl_query) {
            if (onStatus) {
              onStatus('> Translation Complete!');
            }
            finalResult = parsed;
          } else if (parsed.status && onStatus) {
            onStatus(parsed.status);
          }
        } catch (e: any) {
          if (e.message && !e.message.includes('JSON')) {
            throw e;
          }
        }
      }
    }

    if (buffer.trim().startsWith('data:')) {
      const dataStr = buffer.trim().replace(/^data:\s*/, '');
      try {
        const parsed = JSON.parse(dataStr);
        if (parsed.result) {
          if (onStatus) {
            onStatus('> Translation Complete!');
          }
          finalResult = parsed.result;
        } else if (parsed.kql_query && parsed.spl_query) {
          if (onStatus) {
            onStatus('> Translation Complete!');
          }
          finalResult = parsed;
        }
      } catch {
        // ignore
      }
    }

    if (!finalResult) {
      throw new Error('Streaming connection closed before receiving translation payload');
    }
    return finalResult;
  }

  return res.json();
}

export async function validateCustomQuery(
  queryText: string,
  language: 'KQL' | 'SPL',
  requiredTerms: string[],
  exclusionTerms: string[]
): Promise<SingleLanguageValidation> {
  const res = await fetch(`${API_BASE}/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query_text: queryText,
      target_language: language,
      required_terms: requiredTerms,
      exclusion_terms: exclusionTerms,
    }),
  });
  if (!res.ok) {
    throw new Error(`Validation failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function generateRunbook(
  ruleName: string,
  severity: string,
  mitreTactic: string | null,
  rawCondition: string,
  kqlQuery: string,
  splQuery: string,
  llmConfig: LLMConfig
): Promise<{ success: boolean; threat_analysis: ThreatAnalysis }> {
  const res = await fetch(`${API_BASE}/generate-runbook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      rule_name: ruleName,
      severity,
      mitre_tactic: mitreTactic,
      raw_condition: rawCondition,
      kql_query: kqlQuery,
      spl_query: splQuery,
      llm_config: llmConfig,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Threat analysis generation failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function saveRunbook(payload: SaveRunbookRequest): Promise<SaveRunbookResponse> {
  const res = await fetch(`${API_BASE}/save-runbook`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Save runbook failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function testLiveSplunk(
  splQuery: string,
  earliest = '-24h',
  latest = 'now',
  maxEvents = 25
): Promise<LiveSplunkTestResponse> {
  const res = await fetch(`${API_BASE}/test-live-splunk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      spl_query: splQuery,
      earliest_time: earliest,
      latest_time: latest,
      max_events: maxEvents,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `Splunk live search failed: HTTP ${res.status}`);
  }
  return res.json();
}

export async function fetchAuditLog(
  limit = 50,
  offset = 0,
  ruleName?: string
): Promise<AuditLogResponse> {
  const params = new URLSearchParams({
    limit: limit.toString(),
    offset: offset.toString(),
  });
  if (ruleName) params.append('rule_name', ruleName);

  const res = await fetch(`${API_BASE}/audit-log?${params.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch audit history: HTTP ${res.status}`);
  }
  return res.json();
}

