import React from 'react';
import { ThreatAnalysis } from '../api/client';
import { Shield, AlertTriangle, Eye, HelpCircle } from 'lucide-react';

interface ThreatAnalysisViewProps {
  analysis: ThreatAnalysis;
}

export const ThreatAnalysisView: React.FC<ThreatAnalysisViewProps> = ({ analysis }) => {
  return (
    <div className="rounded-2xl border border-white/[0.06] bg-[#07080b]/60 p-6 space-y-6">
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
      <div className="space-y-2">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
          Adversary Threat Summary
        </h4>
        <p className="text-xs sm:text-sm text-zinc-300 bg-[#07080b] p-4 sm:p-5 rounded-xl border border-white/[0.06] leading-relaxed">
          {analysis.threat_summary}
        </p>
      </div>

      {/* Mapped MITRE Techniques Table */}
      {analysis.mitre_techniques && analysis.mitre_techniques.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
            Mapped MITRE ATT&CK Techniques
          </h4>
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
                {analysis.mitre_techniques.map((tech, idx) => (
                  <tr key={idx} className="hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 font-mono text-cyan-300 font-medium">
                      {tech.technique_id}
                    </td>
                    <td className="px-4 py-3 text-zinc-200">{tech.technique_name}</td>
                    <td className="px-4 py-3 text-zinc-400">{tech.tactic}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Detection Review & Gaps */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        {/* False Positive Sources */}
        <div className="rounded-xl border border-white/[0.06] bg-[#07080b] p-4 sm:p-5 space-y-3">
          <div className="flex items-center gap-2 font-semibold text-amber-300">
            <AlertTriangle className="w-4 h-4 stroke-[2] shrink-0" />
            <span>Potential False Positive Sources</span>
          </div>
          <ul className="space-y-1.5 text-zinc-300 list-disc list-inside leading-relaxed">
            {analysis.detection_review?.false_positive_sources?.map((fp, i) => (
              <li key={i}>{fp}</li>
            ))}
          </ul>
        </div>

        {/* Evasion Blindspots */}
        <div className="rounded-xl border border-white/[0.06] bg-[#07080b] p-4 sm:p-5 space-y-3">
          <div className="flex items-center gap-2 font-semibold text-rose-300">
            <Eye className="w-4 h-4 stroke-[2] shrink-0" />
            <span>Evasion Blind Spots</span>
          </div>
          <ul className="space-y-1.5 text-zinc-300 list-disc list-inside leading-relaxed">
            {analysis.detection_review?.evasion_blindspots?.map((ev, i) => (
              <li key={i}>{ev}</li>
            ))}
          </ul>
        </div>
      </div>

      {/* Tier-1 Analyst Triage Guide */}
      <div className="rounded-xl border border-white/[0.06] bg-[#07080b] p-5 sm:p-6 space-y-4">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
          <HelpCircle className="w-4 h-4 text-cyan-400 stroke-[2] shrink-0" />
          <span>Tier-1 Analyst Triage &amp; Containment Playbook</span>
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 text-xs">
          <div className="space-y-2">
            <span className="font-semibold text-zinc-400">Initial Verification Questions:</span>
            <ul className="space-y-1.5 text-zinc-200 list-disc list-inside leading-relaxed">
              {analysis.analyst_triage_guide?.initial_questions?.map((q, i) => (
                <li key={i}>{q}</li>
              ))}
            </ul>
          </div>

          <div className="space-y-2">
            <span className="font-semibold text-zinc-400">Containment Actions:</span>
            <ul className="space-y-1.5 text-zinc-200 list-disc list-inside leading-relaxed">
              {analysis.analyst_triage_guide?.containment_steps?.map((c, i) => (
                <li key={i}>{c}</li>
              ))}
            </ul>
          </div>
        </div>

        {analysis.analyst_triage_guide?.escalation_criteria && (
          <div className="pt-3 border-t border-white/[0.06] text-xs">
            <span className="font-semibold text-rose-300">Escalation Criteria: </span>
            <span className="text-zinc-300 leading-relaxed">
              {analysis.analyst_triage_guide.escalation_criteria.join('; ')}
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
