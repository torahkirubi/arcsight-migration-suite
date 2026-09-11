import React from 'react';
import { ArrowRight, Info } from 'lucide-react';
import { TuningRecommendation } from '../api/client';

export interface TelemetryTunerCardProps { tuning_recommendation?: TuningRecommendation | null; }
export const TelemetryTunerCard: React.FC<TelemetryTunerCardProps> = ({ tuning_recommendation }) => {
  if (!tuning_recommendation) return null;
  return <div className="tuning-recommendation"><div className="tuning-recommendation-head"><div><span className="eyebrow">Lab result / recommendation</span><h3>Noise has a shape.</h3></div><span className="recommendation-mark">sentinel tuned</span></div><div className="threshold-compare"><div><span>Current</span><strong>{tuning_recommendation.original_threshold}</strong><small>events</small></div><ArrowRight size={19} /><div className="suggested"><span>Suggested</span><strong>{tuning_recommendation.suggested_threshold}</strong><small>events</small></div></div><div className="rationale"><Info size={15} /><p>{tuning_recommendation.tuning_rationale}</p></div></div>;
};
