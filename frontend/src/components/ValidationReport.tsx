import React from 'react';
import { CheckCircle2, XCircle, AlertOctagon, Check, ShieldAlert } from 'lucide-react';
import { SingleLanguageValidation } from '../api/client';

interface ValidationReportProps {
  validation: SingleLanguageValidation;
  title: string;
}

export const ValidationReport: React.FC<ValidationReportProps> = ({ validation, title }) => {
  const isPassed = validation.passed;
  const coveragePct = validation.coverage_pct;

  const getScoreColor = (score: number) => {
    if (score >= 90) return 'text-emerald-300 border-emerald-500/30 bg-emerald-500/[0.05]';
    if (score >= 60) return 'text-amber-300 border-amber-500/30 bg-amber-500/[0.05]';
    return 'text-rose-300 border-rose-500/30 bg-rose-500/[0.05]';
  };

  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#07080b]/60 p-4 space-y-4">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
        <div className="flex items-center gap-2">
          {isPassed ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 stroke-[2] shrink-0" />
          ) : (
            <XCircle className="w-4 h-4 text-rose-400 stroke-[2] shrink-0" />
          )}
          <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">{title}</h4>
        </div>
        <div
          className={`px-2.5 py-0.5 rounded-full border text-xs font-medium w-fit ${getScoreColor(
            coveragePct
          )}`}
        >
          {coveragePct}% Coverage ({isPassed ? 'PASSED' : 'CHECK FAILED'})
        </div>
      </div>

      {/* Terms Analysis Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        {/* Required Match Terms */}
        <div className="rounded-lg border border-white/[0.06] bg-[#07080b] p-3 space-y-2">
          <div className="font-medium text-zinc-300 flex items-center justify-between">
            <span>Required Match Terms</span>
            <span className="text-[11px] text-zinc-500 font-mono">
              {validation.required_terms_checked.length - validation.missing_required.length} /{' '}
              {validation.required_terms_checked.length}
            </span>
          </div>
          {validation.required_terms_checked.length === 0 ? (
            <p className="text-zinc-500 italic">No specific match terms required.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {validation.required_terms_checked.map((term) => {
                const isMissing = validation.missing_required.includes(term);
                return (
                  <span
                    key={term}
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md font-mono text-[11px] border ${
                      isMissing
                        ? 'bg-rose-500/[0.08] border-rose-500/30 text-rose-300'
                        : 'bg-emerald-500/[0.08] border-emerald-500/30 text-emerald-300'
                    }`}
                  >
                    {isMissing ? (
                      <XCircle className="w-3 h-3 stroke-[2]" />
                    ) : (
                      <Check className="w-3 h-3 stroke-[2.5]" />
                    )}
                    {term}
                  </span>
                );
              })}
            </div>
          )}
        </div>

        {/* Exclusion Terms */}
        <div className="rounded-lg border border-white/[0.06] bg-[#07080b] p-3 space-y-2">
          <div className="font-medium text-zinc-300 flex items-center justify-between">
            <span>Exclusion Filters (Must Be Negated)</span>
            <span className="text-[11px] text-zinc-500 font-mono">
              {validation.exclusion_terms_checked.length} terms
            </span>
          </div>
          {validation.exclusion_terms_checked.length === 0 ? (
            <p className="text-zinc-500 italic">No exclusions in source rule.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {validation.exclusion_terms_checked.map((term) => {
                const isWronglyIncluded = validation.wrongly_included_as_match.includes(term);
                const isMissing = validation.missing_exclusions.includes(term);
                return (
                  <span
                    key={term}
                    className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md font-mono text-[11px] border ${
                      isWronglyIncluded
                        ? 'bg-rose-500/[0.15] border-rose-500/50 text-rose-200'
                        : isMissing
                        ? 'bg-amber-500/[0.08] border-amber-500/30 text-amber-300'
                        : 'bg-emerald-500/[0.08] border-emerald-500/30 text-emerald-300'
                    }`}
                  >
                    {isWronglyIncluded ? (
                      <AlertOctagon className="w-3 h-3 text-rose-400 stroke-[2]" />
                    ) : isMissing ? (
                      <XCircle className="w-3 h-3 text-amber-400 stroke-[2]" />
                    ) : (
                      <Check className="w-3 h-3 text-emerald-400 stroke-[2.5]" />
                    )}
                    NOT({term})
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Critical Negation Bug Warning */}
      {validation.wrongly_included_as_match.length > 0 && (
        <div className="p-3.5 rounded-xl border border-rose-500/30 bg-rose-500/[0.06] text-xs text-rose-200 flex items-start gap-2.5">
          <ShieldAlert className="w-4 h-4 text-rose-400 stroke-[2] shrink-0 mt-0.5" />
          <div className="leading-relaxed">
            <span className="font-semibold text-rose-100">Dangerous Negation Bug Detected:</span> Terms{' '}
            <code className="font-mono font-semibold text-rose-300 px-1 py-0.5 rounded bg-rose-900/30 border border-rose-500/20">
              {validation.wrongly_included_as_match.join(', ')}
            </code>{' '}
            are included in the query without negation. Alerts would fire on activities intended to be filtered out.
          </div>
        </div>
      )}
    </div>
  );
};
