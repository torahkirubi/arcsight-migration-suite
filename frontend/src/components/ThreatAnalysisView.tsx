import React from 'react';
import { ThreatAnalysis } from '../api/client';
import { Shield, AlertTriangle, Eye, HelpCircle } from 'lucide-react';

interface ThreatAnalysisViewProps {
  analysis: ThreatAnalysis | string | Record<string, any>;
}

export const ThreatAnalysisView: React.FC<ThreatAnalysisViewProps> = ({ analysis }) => {
  const normalized = React.useMemo(() => {
    if (!analysis) return null;
    let data: any = analysis;
    if (typeof analysis === 'string') {
      try {
        const clean = analysis.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
        data = JSON.parse(clean);
      } catch {
        try {
          const match = analysis.match(/(\{[\s\S]*\})/);
          if (match) {
            data = JSON.parse(match[1]);
          } else {
            data = { threat_summary: analysis };
          }
        } catch {
          data = { threat_summary: analysis };
        }
      }
    }
    return data;
  }, [analysis]);

  if (!normalized) return null;

  const threatSummary = normalized.threat_summary || '';

  const tactics: string[] =
    Array.isArray(normalized.mitre_tactics) && normalized.mitre_tactics.length > 0
      ? normalized.mitre_tactics
      : (Array.from(
          new Set(
            (normalized.mitre_techniques || [])
              .map((t: any) => t?.tactic)
              .filter(Boolean)
          )
        ) as string[]);

  const techniques: any[] = Array.isArray(normalized.mitre_techniques) ? normalized.mitre_techniques : [];

  const evasionBlindspots: string[] =
    normalized.evasion_blindspots ||
    normalized.detection_review?.evasion_blindspots ||
    [];

  const falsePositives: string[] =
    normalized.false_positive_sources ||
    normalized.detection_review?.false_positive_sources ||
    [];

  const triageQuestions: string[] =
    normalized.triage_questions ||
    normalized.analyst_triage_guide?.initial_questions ||
    [];

  const containmentSteps: string[] =
    normalized.containment_steps ||
    normalized.analyst_triage_guide?.containment_steps ||
    [];

  const escalationCriteria: string[] =
    normalized.escalation_criteria ||
    normalized.analyst_triage_guide?.escalation_criteria ||
    [];

  return (
    <div className="threat-analysis-card rounded-2xl border border-white/[0.06] bg-[#07080b]/60 p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-white/[0.06] pb-4">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-cyan-400/[0.08] border border-cyan-400/20 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4 stroke-[1.75]" />
          </div>
          <h3 className="text-sm font-semibold text-white tracking-tight">
            Threat Analysis &amp; Detection Runbook
          </h3>
        </div>
        <span className="px-2.5 py-0.5 text-[10px] font-medium rounded-full bg-cyan-400/10 text-cyan-300 border border-cyan-400/20 uppercase tracking-wider w-fit">
          AI Triage Spec
        </span>
      </div>

      {/* Adversary Threat Summary */}
      {threatSummary && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
            Adversary Threat Summary
          </h4>
          <p className="text-xs sm:text-sm text-zinc-300 bg-[#07080b] p-4 sm:p-5 rounded-xl border border-white/[0.06] leading-relaxed">
            {threatSummary}
          </p>
        </div>
      )}

      {/* Mapped MITRE ATT&CK Framework */}
      {(techniques.length > 0 || tactics.length > 0) && (
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
              Mapped MITRE ATT&amp;CK Framework
            </h4>
          </div>

          {tactics.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-medium text-zinc-400">Tactics:</span>
              {tactics.map((tactic, idx) => (
                <span
                  key={idx}
                  className="px-2.5 py-0.5 text-[11px] font-medium rounded-md bg-cyan-400/10 text-cyan-300 border border-cyan-400/20"
                >
                  {tactic}
                </span>
              ))}
            </div>
          )}

          {techniques.length > 0 && (
            <div className="overflow-x-auto rounded-xl border border-white/[0.06] bg-[#07080b]">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-white/[0.06] text-zinc-400 font-medium bg-white/[0.02]">
                  <tr>
                    <th className="px-4 py-3">Technique ID</th>
                    <th className="px-4 py-3">Technique Name</th>
                    <th className="px-4 py-3">Tactic</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.04]">
                  {techniques.map((tech, idx) => (
                    <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 py-3 font-mono text-cyan-300 font-medium">
                        {tech.technique_id}
                      </td>
                      <td className="px-4 py-3 text-zinc-200">{tech.technique_name}</td>
                      <td className="px-4 py-3 text-zinc-400">
                        {tech.tactic ? `Tactic: ${tech.tactic}` : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Detection Review & Gaps */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        {/* False Positive Sources */}
        {falsePositives.length > 0 && (
          <div className="rounded-xl border border-white/[0.06] bg-[#07080b] p-4 sm:p-5 space-y-3">
            <div className="flex items-center gap-2 font-semibold text-amber-300">
              <AlertTriangle className="w-4 h-4 stroke-[2] shrink-0" />
              <span>Potential False Positive Sources</span>
            </div>
            <ul className="space-y-1.5 text-zinc-300 list-disc list-inside leading-relaxed">
              {falsePositives.map((fp, i) => (
                <li key={i}>{fp}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Evasion Blindspots */}
        <div
          className={`rounded-xl border border-white/[0.06] bg-[#07080b] p-4 sm:p-5 space-y-3 ${
            falsePositives.length === 0 ? 'md:col-span-2' : ''
          }`}
        >
          <div className="flex items-center gap-2 font-semibold text-rose-300">
            <Eye className="w-4 h-4 stroke-[2] shrink-0" />
            <span>Evasion Blindspots</span>
          </div>
          <ul className="space-y-1.5 text-zinc-300 list-disc list-inside leading-relaxed">
            {evasionBlindspots.map((ev, i) => (
              <li key={i}>{ev}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Tier 1 Triage Steps */}
      <div className="rounded-xl border border-white/[0.06] bg-[#07080b] p-5 sm:p-6 space-y-4">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-cyan-400 stroke-[2] shrink-0" />
          <span>Tier 1 Triage Steps</span>
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div className="space-y-2">
            <span className="font-semibold text-zinc-400">Initial Verification Questions:</span>
            <ul className="space-y-1.5 text-zinc-200 list-disc list-inside leading-relaxed">
              {triageQuestions.map((q, i) => (
                <li key={i}>{q}</li>
              ))}
            </ul>
          </div>

          {containmentSteps.length > 0 && (
            <div className="space-y-2">
              <span className="font-semibold text-zinc-400">Containment Actions:</span>
              <ul className="space-y-1.5 text-zinc-200 list-disc list-inside leading-relaxed">
                {containmentSteps.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {escalationCriteria.length > 0 && (
          <div className="pt-3 border-t border-white/[0.06] text-xs">
            <span className="font-semibold text-rose-300">Escalation Criteria: </span>
            <span className="text-zinc-300 leading-relaxed">
              {escalationCriteria.join('; ')}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
