import React from 'react';
import { TuningRecommendation } from '../api/client';
import { Sliders, Info } from 'lucide-react';

export interface TelemetryTunerCardProps {
  tuning_recommendation?: TuningRecommendation | null;
}

export const TelemetryTunerCard: React.FC<TelemetryTunerCardProps> = ({
  tuning_recommendation,
}) => {
  if (!tuning_recommendation) {
    return null;
  }

  return (
    <div className="rounded-2xl border border-cyan-500/20 bg-[#0c1017]/80 backdrop-blur-md p-6 sm:p-7 space-y-5 relative overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
            <Sliders className="w-4 h-4 stroke-[1.75]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h3 className="text-base font-semibold text-white tracking-tight">
                Telemetry Baseline & Dynamic Threshold
              </h3>
              <span className="px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                Sentinel Tuned
              </span>
            </div>
            <p className="text-sm text-zinc-400 font-normal mt-0.5">
              Dynamic threshold adjustment calculated from 7-day historical telemetry volume.
            </p>
          </div>
        </div>
      </div>

      {/* Metrics Side-by-Side Comparison */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Original Static Threshold */}
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 flex flex-col justify-between">
          <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">
            Original Static Threshold
          </span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-zinc-200">
              {tuning_recommendation.original_threshold}
            </span>
            <span className="text-xs text-zinc-500 font-medium">events</span>
          </div>
        </div>

        {/* Suggested Dynamic Threshold */}
        <div className="rounded-xl border border-cyan-500/30 bg-cyan-950/[0.15] p-4 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-cyan-300 uppercase tracking-wider">
              Suggested Dynamic Threshold
            </span>
            <span className="px-2 py-0.5 text-[10px] font-medium rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              Recommended
            </span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-cyan-400">
              {tuning_recommendation.suggested_threshold}
            </span>
            <span className="text-xs text-cyan-500/80 font-medium">events</span>
          </div>
        </div>
      </div>

      {/* Tuning Rationale Callout */}
      <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 flex items-start gap-3">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <h4 className="text-xs font-medium uppercase tracking-wider text-zinc-400 mb-1">
            Tuning Rationale
          </h4>
          <p className="text-base text-zinc-300 leading-relaxed font-normal">
            {tuning_recommendation.tuning_rationale}
          </p>
        </div>
      </div>
    </div>
  );
};

