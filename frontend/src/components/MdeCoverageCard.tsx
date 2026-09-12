import React from 'react';
import { UserCheck, AlertCircle } from 'lucide-react';
import { MdeCoverageInput } from '../api/client';

interface MdeCoverageCardProps {
  value: MdeCoverageInput;
  onChange: (updated: MdeCoverageInput) => void;
}

const VERDICT_OPTIONS = [
  'Native MDE Alert Exists (No Custom Rule Required)',
  'Partial / Custom KQL Rule Required (Complementary)',
  'No Native Coverage (Custom KQL Rule Mandatory)',
  'Under Evaluation / Pending Lab Verification',
];

export const MdeCoverageCard: React.FC<MdeCoverageCardProps> = ({ value, onChange }) => {
  return (
    <div className="mde-coverage-card rounded-2xl border border-indigo-500/30 bg-indigo-950/[0.08] backdrop-blur-md p-6 sm:p-7 space-y-6 relative overflow-hidden">
      {/* Safety Boundary Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-indigo-500/20 pb-4">
        <div className="flex items-start sm:items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 shrink-0">
            <UserCheck className="w-4 h-4 stroke-[1.75]" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h3 className="text-sm font-semibold text-white tracking-tight">
                Microsoft Defender (MDE) Native Coverage Assessment
              </h3>
              <span className="px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider rounded-full bg-indigo-500/10 text-indigo-300 border border-indigo-500/30">
                Human-in-the-Loop
              </span>
            </div>
            <p className="text-xs text-indigo-200/70 font-light mt-0.5">
              Strict Safety Boundary: Zero LLM generation permitted. Review and judgment must be entered by an engineer.
            </p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Verdict Selector */}
        <div className="space-y-1.5 md:col-span-2">
          <label className="block text-xs font-medium text-zinc-300">
            Coverage Verdict <span className="text-rose-400">*</span>
          </label>
          <select
            value={value.verdict}
            onChange={(e) => onChange({ ...value, verdict: e.target.value })}
            className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-indigo-400/50 rounded-xl px-4 py-2.5 text-xs sm:text-sm text-zinc-200 focus:outline-none transition-all"
          >
            <option value="">Select Human-Verified Verdict...</option>
            {VERDICT_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
          {!value.verdict && (
            <p className="flex items-center gap-1.5 text-xs text-amber-400/90 mt-1">
              <AlertCircle className="w-3.5 h-3.5 stroke-[2] shrink-0" />
              <span>Verdict is required before Git-ready runbook can be committed.</span>
            </p>
          )}
        </div>

        {/* Reviewer Name */}
        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-zinc-300">
            Assessing Engineer <span className="text-rose-400">*</span>
          </label>
          <input
            type="text"
            value={value.reviewer_name || ''}
            onChange={(e) => onChange({ ...value, reviewer_name: e.target.value })}
            placeholder="e.g. Lead Detection Engineer"
            className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-indigo-400/50 rounded-xl px-4 py-2.5 text-xs sm:text-sm text-zinc-200 focus:outline-none transition-all"
          />
        </div>

        {/* Notes & Justification */}
        <div className="space-y-1.5 md:col-span-3">
          <label className="block text-xs font-medium text-zinc-300">
            Analyst Justification &amp; Telemetry Notes
          </label>
          <textarea
            rows={3}
            value={value.notes}
            onChange={(e) => onChange({ ...value, notes: e.target.value })}
            placeholder="Document testing results, DeviceProcessEvents telemetry availability, or reasons why default alerts do or do not cover this technique..."
            className="w-full bg-[#07080b]/90 border border-white/[0.08] focus:border-indigo-400/50 rounded-xl p-3.5 text-xs sm:text-sm leading-relaxed text-zinc-200 focus:outline-none transition-all font-mono resize-y min-h-[90px]"
          />
        </div>
      </div>
    </div>
  );
};
