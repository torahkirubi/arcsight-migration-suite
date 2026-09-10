import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { TelemetryTunerCard } from './TelemetryTunerCard';
import { TuningRecommendation } from '../api/client';

describe('TelemetryTunerCard Component', () => {
  const mockRecommendation: TuningRecommendation = {
    original_threshold: 5,
    suggested_threshold: 180,
    tuning_rationale: 'Elevated due to baseline of 150',
  };

  it('renders original_threshold, suggested_threshold, and tuning_rationale values to the screen', () => {
    render(<TelemetryTunerCard tuning_recommendation={mockRecommendation} />);

    // Assert exact threshold values and rationale are rendered
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(screen.getByText('180')).toBeInTheDocument();
    expect(screen.getByText('Elevated due to baseline of 150')).toBeInTheDocument();
  });

  it('safely returns null (renders nothing) when tuning_recommendation is undefined', () => {
    const { container } = render(<TelemetryTunerCard tuning_recommendation={undefined} />);
    expect(container.firstChild).toBeNull();
  });

  it('safely returns null (renders nothing) when tuning_recommendation prop is missing', () => {
    const { container } = render(<TelemetryTunerCard />);
    expect(container.firstChild).toBeNull();
  });
});

