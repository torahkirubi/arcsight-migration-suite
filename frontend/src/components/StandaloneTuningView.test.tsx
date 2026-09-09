import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { StandaloneTuningView } from './StandaloneTuningView';

describe('StandaloneTuningView Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
    sessionStorage.setItem('auth_token', 'mock-jwt-test-token');
  });

  it('renders raw KQL textarea, current threshold numeric input, and an Analyze Telemetry button', () => {
    render(<StandaloneTuningView />);

    expect(screen.getByLabelText(/raw kql/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/current threshold/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Analyze Telemetry/i })).toBeInTheDocument();
  });

  it('triggers POST /api/telemetry/tune on submit and renders TelemetryTunerCard when noise_diagnostics is null', async () => {
    const mockTuningResponse = {
      original_threshold: 5,
      suggested_threshold: 240,
      tuning_rationale: 'Historical baseline returned 200 events over evaluation window.',
      noise_diagnostics: null,
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockTuningResponse,
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<StandaloneTuningView />);

    fireEvent.change(screen.getByLabelText(/raw kql/i), {
      target: { value: 'SecurityEvent | where EventID == 4625' },
    });
    fireEvent.change(screen.getByLabelText(/current threshold/i), {
      target: { value: '5' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Telemetry/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/telemetry/tune'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            Authorization: 'Bearer mock-jwt-test-token',
          }),
          body: JSON.stringify({
            raw_kql: 'SecurityEvent | where EventID == 4625',
            current_threshold: 5,
          }),
        })
      );
    });

    // Assert TelemetryTunerCard renders the baseline metrics
    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument();
      expect(screen.getByText('240')).toBeInTheDocument();
      expect(
        screen.getByText('Historical baseline returned 200 events over evaluation window.')
      ).toBeInTheDocument();
    });

    // Verify noise diagnostics section is not rendered
    expect(screen.queryByText(/Noise Source/i)).not.toBeInTheDocument();
  });

  it('renders noise diagnostics UI section when noise_diagnostics object is present in the response', async () => {
    const mockResponseWithDiagnostics = {
      original_threshold: 5,
      suggested_threshold: 240,
      tuning_rationale: 'Elevated threshold to suppress recurring backup noise.',
      noise_diagnostics: {
        noise_source: 'Scheduled Backup Script',
        affected_entities: ['SRV-BACKUP-01.corp.internal', 'svc-backup', '10.0.4.15'],
        mitigation_steps: [
          "Exclude Computer contains 'SRV-BACKUP'",
          "Add maintenance window filter for Account == 'svc-backup'",
        ],
      },
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockResponseWithDiagnostics,
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<StandaloneTuningView />);

    fireEvent.change(screen.getByLabelText(/raw kql/i), {
      target: { value: 'SecurityEvent | where EventID == 4625' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Telemetry/i }));

    // Assert TelemetryTunerCard content
    await waitFor(() => {
      expect(screen.getByText('240')).toBeInTheDocument();
    });

    // Assert Noise Diagnostics section headers and values
    expect(screen.getByText(/Noise Source/i)).toBeInTheDocument();
    expect(screen.getByText('Scheduled Backup Script')).toBeInTheDocument();

    expect(screen.getByText(/Affected Entities/i)).toBeInTheDocument();
    expect(screen.getByText('SRV-BACKUP-01.corp.internal')).toBeInTheDocument();
    expect(screen.getByText('svc-backup')).toBeInTheDocument();
    expect(screen.getByText('10.0.4.15')).toBeInTheDocument();

    expect(screen.getByText(/Mitigation Steps/i)).toBeInTheDocument();
    expect(
      screen.getByText("Exclude Computer contains 'SRV-BACKUP'")
    ).toBeInTheDocument();
    expect(
      screen.getByText("Add maintenance window filter for Account == 'svc-backup'")
    ).toBeInTheDocument();
  });

  it('renders Auto-Mitigated Query section displaying tuned_kql when present in response', async () => {
    const mockResponseWithTunedKql = {
      original_threshold: 5,
      suggested_threshold: 240,
      tuning_rationale: 'Elevated threshold to suppress recurring backup noise.',
      noise_diagnostics: {
        noise_source: 'Scheduled Backup Script',
        affected_entities: ['SRV-BACKUP-01.corp.internal', 'svc-backup', '10.0.4.15'],
        mitigation_steps: [
          "Exclude Computer contains 'SRV-BACKUP'",
          "Add maintenance window filter for Account == 'svc-backup'",
        ],
      },
      tuned_kql:
        "SecurityEvent\n| where EventID == 4625\n| where Object !in ('SRV-BACKUP-01.corp.internal', 'svc-backup', '10.0.4.15')\n| summarize count()",
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockResponseWithTunedKql,
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<StandaloneTuningView />);

    fireEvent.change(screen.getByLabelText(/raw kql/i), {
      target: { value: 'SecurityEvent | where EventID == 4625 | summarize count()' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Telemetry/i }));

    // Assert Auto-Mitigated Query section header and query text
    await waitFor(() => {
      expect(screen.getByText(/Auto-Mitigated Query/i)).toBeInTheDocument();
    });

    expect(
      screen.getByText(/where Object !in \('SRV-BACKUP-01\.corp\.internal', 'svc-backup', '10\.0\.4\.15'\)/)
    ).toBeInTheDocument();
  });

  it('does not render Auto-Mitigated Query section when tuned_kql is null or missing', async () => {
    const mockResponseWithoutTunedKql = {
      original_threshold: 5,
      suggested_threshold: 240,
      tuning_rationale: 'Elevated threshold.',
      noise_diagnostics: {
        noise_source: 'Scheduled Backup Script',
        affected_entities: ['10.0.4.15'],
        mitigation_steps: ['Exclude 10.0.4.15'],
      },
      tuned_kql: null,
    };

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockResponseWithoutTunedKql,
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<StandaloneTuningView />);

    fireEvent.change(screen.getByLabelText(/raw kql/i), {
      target: { value: 'SecurityEvent | where EventID == 4625' },
    });

    fireEvent.click(screen.getByRole('button', { name: /Analyze Telemetry/i }));

    await waitFor(() => {
      expect(screen.getByText('240')).toBeInTheDocument();
    });

    expect(screen.queryByText(/Auto-Mitigated Query/i)).not.toBeInTheDocument();
  });
});

