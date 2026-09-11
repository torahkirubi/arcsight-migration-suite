import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Code2,
  Download,
  FileCode2,
  FileText,
  Play,
  RefreshCw,
  ShieldCheck,
  Sparkles,
  Terminal,
  UserCheck,
  XCircle,
} from 'lucide-react';
import {
  generateRunbook,
  LLMConfig,
  MdeCoverageInput,
  saveRunbook,
  SaveRunbookResponse,
  ThreatAnalysis,
  translateDirect,
  TranslateDirectResponse,
} from '../api/client';
import { MdeCoverageCard } from './MdeCoverageCard';
import { SplunkTestModal } from './SplunkTestModal';
import { ThreatAnalysisView } from './ThreatAnalysisView';

const SAMPLE_RULE = `Rule Name: ADFind Active Directory Reconnaissance Detected
Priority: 7
Matching 5 events in 10 Minutes
groupByFields: deviceHostName, destinationUserName

Conditions:
(attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe" Or deviceCustomString2 Contains "adfind.exe" And (destinationUserName NE "service_account" And (destinationPort NE "80"

Actions:
SetEventField(name, "ADFind Active Directory Reconnaissance Detected")
SetEventField(basePriority, 7)
SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery" />)`;

type WorkspaceTab = 'overview' | 'queries' | 'review' | 'export';

export const DirectTranslateView: React.FC<{ llmConfig: LLMConfig }> = ({ llmConfig }) => {
  const [rawText, setRawText] = useState('');
  const [result, setResult] = useState<TranslateDirectResponse | null>(null);
  const [analysis, setAnalysis] = useState<ThreatAnalysis | null>(null);
  const [mdeCoverage, setMdeCoverage] = useState<MdeCoverageInput>({
    verdict: '',
    notes: '',
    reviewer_name: 'Detection Engineer',
  });
  const [tab, setTab] = useState<WorkspaceTab>('overview');
  const [deepMode, setDeepMode] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [busy, setBusy] = useState<'translate' | 'analysis' | 'export' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<SaveRunbookResponse | null>(null);
  const [splunkOpen, setSplunkOpen] = useState(false);
  const [copied, setCopied] = useState<'kql' | 'spl' | null>(null);

  const canExport = Boolean(result && result.validation.passed && mdeCoverage.verdict.trim());
  const status = useMemo(() => {
    if (!result) return { label: 'Awaiting source', tone: 'neutral' };
    if (!result.validation.passed) return { label: 'Review required', tone: 'danger' };
    return { label: 'Validated', tone: 'good' };
  }, [result]);

  const translate = async () => {
    if (!rawText.trim()) return;
    setBusy('translate');
    setError(null);
    setAnalysis(null);
    setSaved(null);
    setLogs(deepMode ? ['Starting Deep Mode validation loop'] : []);
    try {
      const next = await translateDirect(rawText, llmConfig, deepMode, (message) => setLogs((current) => [...current, message]));
      setResult(next);
      setTab('queries');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Translation failed');
    } finally {
      setBusy(null);
    }
  };

  const createAnalysis = async () => {
    if (!result) return;
    setBusy('analysis');
    setError(null);
    try {
      const parsed = result.parsed_rule;
      const response = await generateRunbook(
        parsed.rule_name,
        parsed.severity,
        parsed.mitre_tactic,
        parsed.raw_condition,
        result.kql_query,
        result.spl_query,
        llmConfig,
      );
      setAnalysis(response.threat_analysis);
      setTab('review');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Runbook analysis failed');
    } finally {
      setBusy(null);
    }
  };

  const exportRunbook = async () => {
    if (!result || !mdeCoverage.verdict.trim()) {
      setError('Complete the human MDE coverage assessment before exporting.');
      setTab('review');
      return;
    }
    setBusy('export');
    setError(null);
    try {
      const parsed = result.parsed_rule;
      const response = await saveRunbook({
        rule_name: parsed.rule_name,
        severity: parsed.severity,
        priority: parsed.priority,
        mitre_tactic: parsed.mitre_tactic,
        mitre_source: parsed.mitre_source,
        mitre_uri: parsed.mitre_uri,
        frequency_str: parsed.frequency.raw_frequency,
        group_by: parsed.group_by_fields,
        kql_query: result.kql_query,
        kql_validation: result.validation.kql,
        spl_query: result.spl_query,
        spl_validation: result.validation.spl,
        threat_analysis: analysis || {
          threat_summary: 'Threat analysis pending',
          mitre_techniques: [],
          detection_review: {},
          analyst_triage_guide: {},
        },
        mde_coverage: mdeCoverage,
        llm_model: llmConfig.model_name,
      });
      setSaved(response);
      setTab('export');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Runbook export failed');
    } finally {
      setBusy(null);
    }
  };

  const copy = async (value: string, type: 'kql' | 'spl') => {
    await navigator.clipboard?.writeText(value);
    setCopied(type);
    window.setTimeout(() => setCopied(null), 1600);
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-col justify-between gap-4 border-b border-[#202832] pb-5 xl:flex-row xl:items-end">
        <div>
          <div className="eyebrow">Migration workspace</div>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight text-white">ArcSight rule migration</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">
            Parse legacy correlation logic deterministically, translate it to KQL and SPL, then review every safety boundary before export.
          </p>
        </div>
        <div className={`status-banner status-${status.tone}`}>
          {status.tone === 'good' ? <CheckCircle2 size={16} /> : status.tone === 'danger' ? <AlertTriangle size={16} /> : <FileText size={16} />}
          {status.label}
        </div>
      </div>

      <section className="workbench-panel p-4 sm:p-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <span className="section-icon"><FileCode2 size={17} /></span>
            <div>
              <div className="eyebrow">01 · Source rule</div>
              <h2 className="mt-1 text-sm font-semibold text-white">Paste an ArcSight export</h2>
            </div>
          </div>
          <button className="button-quiet" onClick={() => setRawText(SAMPLE_RULE)}><Sparkles size={14} /> Load sample</button>
        </div>
        <textarea
          aria-label="Source ArcSight rule"
          value={rawText}
          onChange={(event) => setRawText(event.target.value)}
          placeholder="Paste raw ArcSight XML, HTML, or rule documentation here..."
          className="query-input mt-4 min-h-[190px]"
        />
        <div className="mt-4 flex flex-col gap-3 border-t border-[#202832] pt-4 sm:flex-row sm:items-center sm:justify-between">
          <label className="inline-flex items-center gap-3 text-xs text-slate-400">
            <input type="checkbox" checked={deepMode} onChange={(event) => setDeepMode(event.target.checked)} />
            <span><strong className="font-medium text-slate-200">Deep Mode</strong> · run generated SPL through bounded Splunk validation</span>
          </label>
          <button className="button-primary" onClick={translate} disabled={!rawText.trim() || busy === 'translate'}>
            {busy === 'translate' ? <RefreshCw className="animate-spin" size={15} /> : <Play size={15} />}
            {busy === 'translate' ? 'Translating…' : 'Translate rule'}
          </button>
        </div>
      </section>

      {error && <div className="alert-danger"><AlertTriangle size={16} /><span>{error}</span></div>}

      {busy === 'translate' && deepMode && (
        <section className="workbench-panel p-4">
          <div className="flex items-center gap-2 text-xs font-semibold text-cyan-300"><Terminal size={15} /> Deep Mode activity</div>
          <div className="mt-3 max-h-32 space-y-1 overflow-auto font-mono text-[11px] text-slate-500">
            {logs.map((log, index) => <div key={`${log}-${index}`}><span className="mr-2 text-cyan-500">›</span>{log}</div>)}
          </div>
        </section>
      )}

      {result && (
        <>
          <nav className="workbench-tabs" aria-label="Migration result sections">
            {([
              ['overview', 'Overview', ShieldCheck],
              ['queries', 'Queries', Code2],
              ['review', 'Review', UserCheck],
              ['export', 'Export', Download],
            ] as const).map(([id, label, Icon]) => (
              <button key={id} className={tab === id ? 'workbench-tab workbench-tab-active' : 'workbench-tab'} onClick={() => setTab(id)}>
                <Icon size={15} /> {label}
              </button>
            ))}
          </nav>

          {tab === 'overview' && <Overview result={result} onQueries={() => setTab('queries')} />}
          {tab === 'queries' && (
            <QueryWorkspace
              result={result}
              copied={copied}
              onCopy={copy}
              onSplunk={() => setSplunkOpen(true)}
            />
          )}
          {tab === 'review' && (
            <ReviewWorkspace
              result={result}
              analysis={analysis}
              coverage={mdeCoverage}
              busy={busy}
              onCoverage={setMdeCoverage}
              onAnalysis={createAnalysis}
              onExport={exportRunbook}
            />
          )}
          {tab === 'export' && (
            <ExportWorkspace saved={saved} canExport={canExport} busy={busy} onExport={exportRunbook} />
          )}
        </>
      )}

      <SplunkTestModal isOpen={splunkOpen} onClose={() => setSplunkOpen(false)} splQuery={result?.spl_query || ''} />
    </div>
  );
};

const Overview: React.FC<{ result: TranslateDirectResponse; onQueries: () => void }> = ({ result, onQueries }) => {
  const parsed = result.parsed_rule;
  return (
    <div className="grid gap-4 xl:grid-cols-[1fr_330px]">
      <div className="workbench-panel p-5">
        <div className="eyebrow">Parsed metadata</div>
        <h2 className="mt-2 text-xl font-semibold text-white">{parsed.rule_name}</h2>
        <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Severity" value={`${parsed.severity} · ${parsed.priority}/10`} />
          <Metric label="Frequency" value={parsed.frequency.raw_frequency || 'Not specified'} />
          <Metric label="MITRE tactic" value={parsed.mitre_tactic || 'Needs review'} />
          <Metric label="Grouped fields" value={parsed.group_by_fields.join(', ') || 'None'} />
        </div>
        <div className="mt-5 border-t border-[#202832] pt-4">
          <div className="eyebrow">Condition clauses</div>
          <div className="mt-3 space-y-2">
            {parsed.clauses.length ? parsed.clauses.map((clause, index) => (
              <div key={`${clause.raw_clause}-${index}`} className="flex flex-wrap items-center gap-2 border-b border-[#202832] py-2 font-mono text-xs">
                <span className="text-cyan-300">{clause.field_name}</span>
                <span className="text-slate-600">{clause.operator}</span>
                <span className={clause.is_negated ? 'text-amber-300' : 'text-slate-300'}>{clause.value}</span>
                {clause.is_negated && <span className="tag-warning">EXCLUSION</span>}
              </div>
            )) : <p className="text-sm text-slate-500">No structured clauses were extracted.</p>}
          </div>
        </div>
      </div>
      <div className="space-y-4">
        <TermList title="Required terms" terms={parsed.required_terms} tone="good" />
        <TermList title="Exclusion terms" terms={parsed.exclusion_terms} tone="warn" />
        <button className="button-primary w-full" onClick={onQueries}><Code2 size={15} /> Review generated queries <ChevronRight size={15} /></button>
      </div>
    </div>
  );
};

const QueryWorkspace: React.FC<{
  result: TranslateDirectResponse;
  copied: 'kql' | 'spl' | null;
  onCopy: (value: string, type: 'kql' | 'spl') => void;
  onSplunk: () => void;
}> = ({ result, copied, onCopy, onSplunk }) => (
  <div className="grid gap-4 xl:grid-cols-2">
    <QueryPanel title="Microsoft Defender / Sentinel" language="KQL" query={result.kql_query} validation={result.validation.kql} copied={copied === 'kql'} onCopy={() => onCopy(result.kql_query, 'kql')} />
    <QueryPanel title="Splunk Enterprise / Cloud" language="SPL" query={result.spl_query} validation={result.validation.spl} copied={copied === 'spl'} onCopy={() => onCopy(result.spl_query, 'spl')} action={<button className="button-quiet" onClick={onSplunk}><Play size={13} /> Test live</button>} />
  </div>
);

const QueryPanel: React.FC<{
  title: string;
  language: string;
  query: string;
  validation: TranslateDirectResponse['validation']['kql'];
  copied: boolean;
  onCopy: () => void;
  action?: React.ReactNode;
}> = ({ title, language, query, validation, copied, onCopy, action }) => (
  <section className="workbench-panel overflow-hidden">
    <div className="flex items-center justify-between border-b border-[#202832] px-4 py-3">
      <div><div className="eyebrow">{language}</div><h2 className="mt-1 text-sm font-semibold text-white">{title}</h2></div>
      <div className="flex items-center gap-2">{action}<button className="icon-button" onClick={onCopy} title={`Copy ${language}`} aria-label={`Copy ${language}`}>{copied ? <Check size={15} /> : <Clipboard size={15} />}</button></div>
    </div>
    <pre className="query-output min-h-[330px]">{query}</pre>
    <div className={`border-t px-4 py-3 ${validation.passed ? 'border-emerald-900/70 bg-emerald-950/20' : 'border-rose-900/70 bg-rose-950/20'}`}>
      <div className="flex items-center justify-between text-xs">
        <span className="flex items-center gap-2 font-medium text-slate-200">{validation.passed ? <CheckCircle2 className="text-emerald-400" size={15} /> : <XCircle className="text-rose-400" size={15} />} Coverage validation</span>
        <span className={validation.passed ? 'text-emerald-300' : 'text-rose-300'}>{validation.coverage_pct}%</span>
      </div>
      {!validation.passed && <p className="mt-2 text-xs leading-5 text-rose-300">{validation.notes.join(' ') || 'Review missing required terms or negations.'}</p>}
    </div>
  </section>
);

const ReviewWorkspace: React.FC<{
  result: TranslateDirectResponse;
  analysis: ThreatAnalysis | null;
  coverage: MdeCoverageInput;
  busy: 'translate' | 'analysis' | 'export' | null;
  onCoverage: (value: MdeCoverageInput) => void;
  onAnalysis: () => void;
  onExport: () => void;
}> = ({ result, analysis, coverage, busy, onCoverage, onAnalysis, onExport }) => (
  <div className="space-y-4">
    <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
      <section className="workbench-panel p-5">
        <div className="flex items-center justify-between"><div><div className="eyebrow">Threat analysis</div><h2 className="mt-1 text-base font-semibold text-white">Operational runbook</h2></div><button className="button-secondary" onClick={onAnalysis} disabled={busy === 'analysis'}>{busy === 'analysis' ? <RefreshCw className="animate-spin" size={14} /> : <Sparkles size={14} />} {analysis ? 'Regenerate' : 'Generate'}</button></div>
        {analysis ? <div className="mt-4"><ThreatAnalysisView analysis={analysis} /></div> : <p className="mt-5 text-sm leading-6 text-slate-500">Generate a threat summary, ATT&amp;CK mapping, false-positive review, and analyst triage guide.</p>}
      </section>
      <MdeCoverageCard value={coverage} onChange={onCoverage} />
    </div>
    <div className="flex flex-col justify-between gap-3 border border-[#202832] bg-[#0b0f13] p-4 sm:flex-row sm:items-center">
      <div className="flex items-start gap-3 text-xs text-slate-400"><UserCheck className="mt-0.5 text-cyan-300" size={16} /><span>Human MDE coverage is required before the runbook can be written to the Git-ready output directory.</span></div>
      <button className="button-primary" disabled={!result.validation.passed || !coverage.verdict.trim() || busy === 'export'} onClick={onExport}><Download size={15} /> {busy === 'export' ? 'Exporting…' : 'Prepare export'}</button>
    </div>
  </div>
);

const ExportWorkspace: React.FC<{ saved: SaveRunbookResponse | null; canExport: boolean; busy: boolean | string | null; onExport: () => void }> = ({ saved, canExport, busy, onExport }) => (
  <section className="workbench-panel p-5">
    <div className="eyebrow">Git-ready output</div>
    <h2 className="mt-1 text-xl font-semibold text-white">Export reviewed detection package</h2>
    <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-500">The backend combines parsed metadata, validated KQL/SPL, threat analysis, and the human MDE verdict into an auditable runbook.</p>
    {!saved && <button className="button-primary mt-6" disabled={!canExport || Boolean(busy)} onClick={onExport}><Download size={15} /> Write runbook</button>}
    {saved && <div className="mt-6 border border-emerald-900/70 bg-emerald-950/20 p-4"><div className="flex items-center gap-2 text-sm font-medium text-emerald-300"><CheckCircle2 size={16} /> Runbook saved</div><p className="mt-2 font-mono text-xs text-slate-300">{saved.filename}</p><details className="mt-4"><summary className="cursor-pointer text-xs text-slate-400">Preview generated content</summary><pre className="query-output mt-3 max-h-96">{saved.content}</pre></details></div>}
  </section>
);

const Metric: React.FC<{ label: string; value: string }> = ({ label, value }) => <div><div className="eyebrow">{label}</div><div className="mt-1 text-sm text-slate-200">{value}</div></div>;
const TermList: React.FC<{ title: string; terms: string[]; tone: 'good' | 'warn' }> = ({ title, terms, tone }) => <div className="workbench-panel p-4"><div className="eyebrow">{title}</div><div className="mt-3 flex flex-wrap gap-2">{terms.length ? terms.map((term) => <span key={term} className={tone === 'good' ? 'tag-good' : 'tag-warning'}>{term}</span>) : <span className="text-xs text-slate-600">None extracted</span>}</div></div>;
