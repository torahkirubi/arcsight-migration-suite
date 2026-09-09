import React, { useState } from 'react';
import {
  LLMConfig,
  TranslateDirectResponse,
  ThreatAnalysis,
  MdeCoverageInput,
  SaveRunbookResponse,
  translateDirect,
  generateRunbook,
  saveRunbook,
} from '../api/client';
import { MitreBadge } from './MitreBadge';
import { MdeCoverageCard } from './MdeCoverageCard';
import { ValidationReport } from './ValidationReport';
import { ThreatAnalysisView } from './ThreatAnalysisView';
import { TelemetryTunerCard } from './TelemetryTunerCard';
import { GitExportViewer } from './GitExportViewer';
import { SplunkTestModal } from './SplunkTestModal';
import {
  Sparkles,
  Copy,
  Check,
  FileCode2,
  Database,
  ShieldCheck,
  AlertTriangle,
  FileDown,
  ChevronDown,
  ChevronUp,
  Terminal,
  ArrowRight,
  Sliders,
} from 'lucide-react';

const SAMPLE_ARCSIGHT_RULE = `Rule Name: ADFind Active Directory Reconnaissance Detected
Priority: 7
Matching 5 events in 10 Minutes
groupByFields: deviceHostName, destinationUserName

Conditions:
(attackerServiceName EQ "cmd.exe" And (deviceCustomString1 Contains "adfind.exe" Or deviceCustomString2 Contains "adfind.exe" And (destinationUserName NE "service_account" And (destinationPort NE "80"

Actions:
SetEventField(name, "ADFind Active Directory Reconnaissance Detected")
SetEventField(basePriority, 7)
SetEventField(eventAnnotationStage, <Resource URI="/All Stages/MITRE Tactics/Discovery" />)`;

interface DirectTranslateViewProps {
  llmConfig: LLMConfig;
}

export const DirectTranslateView: React.FC<DirectTranslateViewProps> = ({ llmConfig }) => {
  const [rawText, setRawText] = useState('');
  const [isTranslating, setIsTranslating] = useState(false);
  const [translationResult, setTranslationResult] = useState<TranslateDirectResponse | null>(null);
  const [translationError, setTranslationError] = useState<string | null>(null);

  // Threat Analysis state
  const [isGeneratingRunbook, setIsGeneratingRunbook] = useState(false);
  const [threatAnalysis, setThreatAnalysis] = useState<ThreatAnalysis | null>(null);

  // Human MDE Coverage state
  const [mdeCoverage, setMdeCoverage] = useState<MdeCoverageInput>({
    verdict: '',
    notes: '',
    reviewer_name: 'Detection Engineer',
  });

  // Export Viewer state
  const [isSaving, setIsSaving] = useState(false);
  const [savedRunbook, setSavedRunbook] = useState<SaveRunbookResponse | null>(null);
  const [isExportOpen, setIsExportOpen] = useState(false);

  // Diagnostic accordion state
  const [showDiagnostics, setShowDiagnostics] = useState(false);

  // Live Splunk modal state
  const [isSplunkModalOpen, setIsSplunkModalOpen] = useState(false);

  // Deep Mode state
  const [deepMode, setDeepMode] = useState(false);
  const [deepLogs, setDeepLogs] = useState<string[]>([]);

  // Copy states
  const [copiedKql, setCopiedKql] = useState(false);
  const [copiedSpl, setCopiedSpl] = useState(false);

  const handleTranslate = async () => {
    if (!rawText.trim()) return;
    setIsTranslating(true);
    setTranslationError(null);
    setThreatAnalysis(null);
    setDeepLogs(deepMode ? ['Initializing autonomous Deep Mode session...'] : []);
    try {
      const res = await translateDirect(
        rawText,
        llmConfig,
        deepMode,
        (statusText: string) => {
          setDeepLogs((prev) => [...prev, statusText]);
        }
      );
      setTranslationResult(res);
    } catch (err: any) {
      setTranslationError(err.message || 'Direct translation failed');
    } finally {
      setIsTranslating(false);
    }
  };

  const handleGenerateRunbook = async () => {
    if (!translationResult) return;
    setIsGeneratingRunbook(true);
    try {
      const p = translationResult.parsed_rule;
      const res = await generateRunbook(
        p.rule_name,
        p.severity,
        p.mitre_tactic,
        p.raw_condition,
        translationResult.kql_query,
        translationResult.spl_query,
        llmConfig
      );
      setThreatAnalysis(res.threat_analysis);
    } catch (err: any) {
      alert(`Threat analysis generation failed: ${err.message}`);
    } finally {
      setIsGeneratingRunbook(false);
    }
  };

  const handleSaveAndExport = async () => {
    if (!translationResult) return;
    if (!mdeCoverage.verdict.trim()) {
      alert('Safety Requirement: Please select an MDE Coverage Verdict before exporting.');
      return;
    }

    setIsSaving(true);
    try {
      const p = translationResult.parsed_rule;
      const res = await saveRunbook({
        rule_name: p.rule_name,
        severity: p.severity,
        priority: p.priority,
        mitre_tactic: p.mitre_tactic,
        mitre_source: p.mitre_source,
        mitre_uri: p.mitre_uri,
        frequency_str: p.frequency.raw_frequency,
        group_by: p.group_by_fields,
        kql_query: translationResult.kql_query,
        kql_validation: translationResult.validation.kql,
        spl_query: translationResult.spl_query,
        spl_validation: translationResult.validation.spl,
        threat_analysis: threatAnalysis || {
          threat_summary: 'Pending threat analysis generation',
          mitre_techniques: [],
          detection_review: {
            false_positive_sources: [],
            evasion_blindspots: [],
            time_window_evaluation: '',
            missing_triage_fields: [],
          },
          analyst_triage_guide: {
            triage_priority: p.severity,
            initial_questions: [],
            containment_steps: [],
            escalation_criteria: [],
          },
          rule_naming_suggestions: [p.rule_name],
        },
        mde_coverage: mdeCoverage,
        llm_model: llmConfig.model_name || 'qwen2.5-coder',
      });
      setSavedRunbook(res);
      setIsExportOpen(true);
    } catch (err: any) {
      alert(`Save runbook failed: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const copyToClipboard = (text: string, type: 'kql' | 'spl') => {
    navigator.clipboard.writeText(text);
    if (type === 'kql') {
      setCopiedKql(true);
      setTimeout(() => setCopiedKql(false), 2000);
    } else {
      setCopiedSpl(true);
      setTimeout(() => setCopiedSpl(false), 2000);
    }
  };

  return (
    <div className="space-y-6 sm:space-y-8 w-full pb-16">
      {/* Top Raw Rule Ingestion Card */}
      <div className="rounded-2xl border border-white/[0.07] bg-[#0c0d14]/80 backdrop-blur-md p-6 sm:p-8 shadow-sm space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.06] pb-5">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-cyan-400">
              <FileCode2 className="w-4 h-4 stroke-[1.75]" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-white tracking-tight">
                Source ArcSight ESM Rule
              </h2>
              <p className="text-base text-zinc-400 font-light mt-0.5">
                Deterministic regex boundary parsing. Zero LLM involvement in condition extraction.
              </p>
            </div>
          </div>
          <button
            onClick={() => setRawText(SAMPLE_ARCSIGHT_RULE)}
            className="flex items-center gap-1.5 text-xs font-medium text-cyan-400/90 hover:text-cyan-300 self-start sm:self-auto transition-colors"
          >
            <span>Load Sample ADfind Rule</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <textarea
          rows={7}
          value={rawText}
          onChange={(e) => setRawText(e.target.value)}
          placeholder="Paste raw ArcSight ESM XML, HTML, or rule documentation text here..."
          className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-cyan-400/50 focus:ring-1 focus:ring-cyan-400/20 rounded-xl p-4 sm:p-5 font-mono text-xs sm:text-sm text-zinc-200 focus:outline-none transition-all resize-y leading-relaxed min-h-[160px]"
        />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
          <div className="flex items-center gap-2 text-base text-zinc-400">
            <Sliders className="w-3.5 h-3.5 text-zinc-500" />
            <span>Target Engine:</span>
            <span className="text-zinc-200 font-medium">{llmConfig.provider}</span>
            <span className="text-zinc-500">({llmConfig.model_name || 'qwen2.5-coder'})</span>
          </div>

          <div className="flex items-center gap-3">
            {/* Deep Mode Toggle Switch (DESIGN.md compliant) */}
            <button
              type="button"
              role="switch"
              aria-checked={deepMode}
              onClick={() => setDeepMode(!deepMode)}
              className="flex items-center gap-2.5 px-3 py-2 rounded-sm border border-slate-800 bg-slate-900 hover:bg-slate-800/80 transition-colors text-xs font-medium cursor-pointer"
              title="Autonomous testing and self-correction against local Splunk container"
            >
              <span className="text-slate-300 select-none">Deep Mode</span>
              <div
                className={`w-8 h-4 rounded-sm border border-slate-800 p-0.5 flex items-center transition-colors ${
                  deepMode ? 'bg-cyan-500' : 'bg-slate-900'
                }`}
              >
                <div
                  className={`w-3 h-3 rounded-none transition-transform duration-150 ${
                    deepMode ? 'translate-x-3.5 bg-slate-950' : 'translate-x-0 bg-slate-500'
                  }`}
                />
              </div>
            </button>

            <button
              onClick={handleTranslate}
              disabled={isTranslating || !rawText.trim()}
              className="flex items-center justify-center gap-2.5 px-6 py-2.5 rounded-sm bg-cyan-500 hover:bg-cyan-400 disabled:opacity-40 text-slate-950 font-semibold text-xs sm:text-sm transition-all duration-150 cursor-pointer"
            >
              <Sparkles className={`w-4 h-4 stroke-[2] ${isTranslating ? 'animate-spin' : ''}`} />
              <span>
                {isTranslating
                  ? deepMode
                    ? 'Autonomous Deep Validation...'
                    : 'Synthesizing Queries...'
                  : deepMode
                  ? 'Deep Translate (Splunk Loop)'
                  : 'Translate to KQL & SPL'}
              </span>
            </button>
          </div>
        </div>

        {/* Streamed Status Terminal Block (DESIGN.md compliant) */}
        {deepMode && (isTranslating || deepLogs.length > 0) && (
          <div className="font-mono text-sm text-slate-400 bg-slate-950 p-3 border border-slate-800 rounded-sm space-y-2">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2 text-xs text-slate-500">
              <div className="flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span className="text-slate-300 font-semibold tracking-wide">Deep Mode Autonomous Splunk Loop</span>
              </div>
              {isTranslating && (
                <div className="flex items-center gap-1.5 text-cyan-400 font-mono text-[11px]">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                  <span>ACTIVE</span>
                </div>
              )}
            </div>
            <div className="space-y-1 max-h-48 overflow-y-auto pt-1 font-mono text-xs sm:text-sm">
              {deepLogs.map((log, idx) => (
                <div key={idx} className="flex items-start gap-2">
                  <span className="text-cyan-500/80 select-none">&gt;</span>
                  <span className={idx === deepLogs.length - 1 && isTranslating ? 'text-cyan-200' : 'text-slate-400'}>
                    {log}
                  </span>
                </div>
              ))}
              {isTranslating && (
                <div className="flex items-center gap-2 text-cyan-400/60 pt-0.5 animate-pulse">
                  <span className="select-none">&gt;</span>
                  <span className="inline-block w-2 h-3.5 bg-cyan-400/80 align-middle" />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Translation Error Banner */}
        {translationError && (
          <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/[0.05] text-rose-300 text-base flex items-start gap-3">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400 stroke-[1.75]" />
            <div className="space-y-1">
              <div className="font-semibold text-rose-200">Translation Engine Exception</div>
              <p className="text-zinc-400 text-base leading-relaxed">{translationError}</p>
              <div className="text-zinc-400 text-base mt-1">
                Please verify your LLM service is active at{' '}
                <code className="font-mono bg-black/40 px-1.5 py-0.5 rounded border border-white/[0.08] text-zinc-300 text-sm leading-relaxed">
                  {llmConfig.custom_base_url || 'http://localhost:1234/v1'}
                </code>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Main Workspace (Rendered once translated) */}
      {translationResult && (
        <div className="space-y-6 sm:space-y-8">
          {/* Deterministic Extraction Specification Strip */}
          <div className="rounded-2xl border border-white/[0.07] bg-[#0c0d14]/80 backdrop-blur-md p-6 sm:p-8 space-y-6">
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-emerald-500/[0.08] border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <ShieldCheck className="w-4 h-4 stroke-[1.75]" />
                </div>
                <h3 className="text-sm font-semibold text-white tracking-tight">
                  Deterministic Extraction Specification
                </h3>
              </div>
              <span className="px-2.5 py-0.5 text-[10px] font-medium tracking-wider uppercase rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Zero LLM Involvement
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6">
              {/* Rule Name */}
              <div className="md:col-span-2 space-y-1">
                <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                  Rule Name
                </span>
                <div className="text-base font-semibold text-white">
                  {translationResult.parsed_rule.rule_name}
                </div>
              </div>

              {/* Severity & Priority */}
              <div className="space-y-1">
                <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                  Severity / Priority
                </span>
                <div className="flex items-center gap-2.5">
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${
                      translationResult.parsed_rule.severity === 'Critical'
                        ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                        : translationResult.parsed_rule.severity === 'High'
                        ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                        : 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                    }`}
                  >
                    {translationResult.parsed_rule.severity}
                  </span>
                  <span className="text-xs text-zinc-400 font-mono">
                    ({translationResult.parsed_rule.priority}/10)
                  </span>
                </div>
              </div>

              {/* MITRE ATT&CK */}
              <MitreBadge
                tactic={translationResult.parsed_rule.mitre_tactic}
                source={translationResult.parsed_rule.mitre_source}
                rawUri={translationResult.parsed_rule.mitre_uri}
                onTacticChange={(newTactic) => {
                  translationResult.parsed_rule.mitre_tactic = newTactic;
                }}
              />

              {/* Threshold & Frequency */}
              <div className="md:col-span-2 space-y-1">
                <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                  Aggregation &amp; Time Window
                </span>
                <div className="text-xs text-zinc-300 font-mono bg-[#07080b]/90 px-3.5 py-2 rounded-xl border border-white/[0.06]">
                  {translationResult.parsed_rule.frequency.raw_frequency}
                </div>
              </div>

              {/* Group By */}
              <div className="md:col-span-2 space-y-1">
                <span className="text-[11px] font-medium uppercase tracking-wider text-zinc-400">
                  Grouped Fields
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {translationResult.parsed_rule.group_by_fields.length > 0 ? (
                    translationResult.parsed_rule.group_by_fields.map((f) => (
                      <span
                        key={f}
                        className="px-2.5 py-1 rounded-lg text-xs font-mono bg-white/[0.03] text-zinc-300 border border-white/[0.08]"
                      >
                        {f}
                      </span>
                    ))
                  ) : (
                    <span className="text-base text-zinc-500 italic">None (Realtime single-event)</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Dual-Pane Comparison Grid (KQL vs SPL) */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
            {/* KQL Panel */}
            <div className="rounded-2xl border border-white/[0.07] bg-[#0c0d14]/80 backdrop-blur-md p-6 sm:p-7 space-y-5 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-white/[0.06] pb-3.5">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 text-[10px] font-semibold tracking-wider rounded-md bg-cyan-400/10 text-cyan-300 border border-cyan-400/20">
                      KQL
                    </span>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                      Microsoft Defender XDR
                    </h3>
                  </div>
                  <button
                    onClick={() => copyToClipboard(translationResult.kql_query, 'kql')}
                    className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white px-2.5 py-1 rounded-lg border border-white/[0.08] hover:bg-white/[0.05] transition-all"
                    title="Copy KQL Query"
                  >
                    {copiedKql ? <Check className="w-3.5 h-3.5 text-emerald-400 stroke-[2]" /> : <Copy className="w-3.5 h-3.5 stroke-[1.75]" />}
                    <span>{copiedKql ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>

                <div className="bg-[#07080b]/90 rounded-xl border border-white/[0.06] p-4 sm:p-5 min-h-[320px] max-h-[460px] overflow-y-auto font-mono text-sm text-cyan-200/90 leading-relaxed">
                  <pre className="whitespace-pre-wrap text-sm leading-relaxed">{translationResult.kql_query}</pre>
                </div>
              </div>

              {/* Coverage Validation */}
              <ValidationReport
                validation={translationResult.validation.kql}
                title="KQL Detection Coverage Audit"
              />
            </div>

            {/* SPL Panel */}
            <div className="rounded-2xl border border-white/[0.07] bg-[#0c0d14]/80 backdrop-blur-md p-6 sm:p-7 space-y-5 flex flex-col justify-between">
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-white/[0.06] pb-3.5">
                  <div className="flex items-center gap-2.5">
                    <span className="px-2 py-0.5 text-[10px] font-semibold tracking-wider rounded-md bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                      SPL
                    </span>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                      Splunk Enterprise / Cloud
                    </h3>
                    {translationResult.deep_mode && (
                      <span
                        className={`px-2 py-0.5 text-[10px] font-mono border rounded-sm ${
                          translationResult.deep_mode_passed
                            ? 'border-emerald-500/40 bg-emerald-950/30 text-emerald-300'
                            : 'border-amber-500/40 bg-amber-950/30 text-amber-300'
                        }`}
                      >
                        Deep Mode:{' '}
                        {translationResult.deep_mode_passed
                          ? `Validated (${translationResult.deep_mode_attempts || 1}/3)`
                          : 'Fallback Warning'}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setIsSplunkModalOpen(true)}
                      className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 px-2.5 py-1 rounded-lg bg-emerald-500/[0.06] border border-emerald-500/30 hover:bg-emerald-500/[0.1] transition-all font-medium"
                    >
                      <Database className="w-3.5 h-3.5 stroke-[1.75]" />
                      <span>Test Live</span>
                    </button>
                    <button
                      onClick={() => copyToClipboard(translationResult.spl_query, 'spl')}
                      className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white px-2.5 py-1 rounded-lg border border-white/[0.08] hover:bg-white/[0.05] transition-all"
                      title="Copy SPL Query"
                    >
                      {copiedSpl ? <Check className="w-3.5 h-3.5 text-emerald-400 stroke-[2]" /> : <Copy className="w-3.5 h-3.5 stroke-[1.75]" />}
                      <span>{copiedSpl ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                </div>

                <div className="bg-[#07080b]/90 rounded-xl border border-white/[0.06] p-4 sm:p-5 min-h-[320px] max-h-[460px] overflow-y-auto font-mono text-sm text-emerald-200/90 leading-relaxed">
                  <pre className="whitespace-pre-wrap text-sm leading-relaxed">{translationResult.spl_query}</pre>
                </div>
              </div>

              {/* Coverage Validation */}
              <ValidationReport
                validation={translationResult.validation.spl}
                title="SPL Detection Coverage Audit"
              />
            </div>
          </div>

          {/* Historical Telemetry Baseline & Dynamic Threshold Card */}
          <TelemetryTunerCard tuning_recommendation={translationResult.tuning_recommendation} />

          {/* Threat Analysis & Playbook */}
          <div className="rounded-2xl border border-white/[0.07] bg-[#0c0d14]/80 backdrop-blur-md p-6 sm:p-8 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-base font-semibold text-white tracking-tight">
                  Threat Analysis &amp; Analyst Triage Guide
                </h3>
                <p className="text-base text-zinc-400 font-light mt-0.5">
                  Automated synthesis of SOC investigation questions, evasion blindspots, and MITRE mapping.
                </p>
              </div>
              <button
                onClick={handleGenerateRunbook}
                disabled={isGeneratingRunbook}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white/[0.04] hover:bg-white/[0.08] text-cyan-300 border border-white/[0.1] text-xs font-medium transition-all duration-150 cursor-pointer self-start sm:self-auto"
              >
                <Sparkles className={`w-3.5 h-3.5 stroke-[1.75] ${isGeneratingRunbook ? 'animate-spin' : ''}`} />
                <span>{isGeneratingRunbook ? 'Synthesizing...' : 'Generate Threat Runbook'}</span>
              </button>
            </div>

            {threatAnalysis && <ThreatAnalysisView analysis={threatAnalysis} />}
          </div>

          {/* Human MDE Coverage Assessment Card (Strict Safety Boundary) */}
          <MdeCoverageCard value={mdeCoverage} onChange={setMdeCoverage} />

          {/* Collapsible Diagnostic & Stream View */}
          <div className="rounded-2xl border border-white/[0.06] bg-[#0c0d14]/50 overflow-hidden">
            <button
              onClick={() => setShowDiagnostics(!showDiagnostics)}
              className="w-full flex items-center justify-between p-4 px-6 text-left hover:bg-white/[0.02] transition-colors"
            >
              <div className="flex items-center gap-2.5 text-base font-medium text-zinc-400">
                <Terminal className="w-4 h-4 stroke-[1.75] text-zinc-500" />
                <span>Engine Diagnostic Log &amp; Raw Completion Stream</span>
              </div>
              {showDiagnostics ? (
                <ChevronUp className="w-4 h-4 text-zinc-500 stroke-[1.75]" />
              ) : (
                <ChevronDown className="w-4 h-4 text-zinc-500 stroke-[1.75]" />
              )}
            </button>
            {showDiagnostics && (
              <div className="p-6 border-t border-white/[0.06] bg-[#07080b]/90 space-y-2.5">
                <div className="text-[11px] font-medium uppercase tracking-wider text-zinc-500">
                  Raw Output Stream
                </div>
                <pre className="p-4 rounded-xl border border-white/[0.06] bg-[#07080b] font-mono text-sm text-zinc-400 whitespace-pre-wrap max-h-56 overflow-y-auto leading-relaxed">
                  {translationResult.raw_llm_output}
                </pre>
              </div>
            )}
          </div>

          {/* Bottom Git-Ready Artifact Strip */}
          <div className="rounded-2xl border border-white/[0.08] bg-[#0c0d14]/90 backdrop-blur-md p-6 sm:p-8 flex flex-col sm:flex-row sm:items-center justify-between gap-6">
            <div className="space-y-1">
              <h3 className="text-base font-semibold text-white tracking-tight">
                Final Detection Engineering Artifact
              </h3>
              <p className="text-base text-zinc-400 font-light">
                Merges deterministic metadata, validated queries, AI triage runbook, and human MDE verdict into a git-ready specification.
              </p>
            </div>

            <button
              onClick={handleSaveAndExport}
              disabled={isSaving || !mdeCoverage.verdict.trim()}
              className="flex items-center justify-center gap-2.5 px-6 py-3 rounded-xl bg-white hover:bg-zinc-100 disabled:opacity-30 text-[#07080b] font-semibold text-xs sm:text-sm shadow-[0_0_20px_rgba(255,255,255,0.1)] transition-all duration-200 cursor-pointer shrink-0"
            >
              <FileDown className="w-4 h-4 stroke-[2]" />
              <span>{isSaving ? 'Assembling Artifact...' : 'Save & Export Git-Ready .txt'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Modals */}
      <SplunkTestModal
        isOpen={isSplunkModalOpen}
        onClose={() => setIsSplunkModalOpen(false)}
        splQuery={translationResult?.spl_query || ''}
      />

      <GitExportViewer
        isOpen={isExportOpen}
        onClose={() => setIsExportOpen(false)}
        result={savedRunbook}
      />
    </div>
  );
};
