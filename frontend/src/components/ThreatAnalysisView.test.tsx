import React from 'react';
import { render, screen } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { ThreatAnalysisView } from './ThreatAnalysisView';

describe('ThreatAnalysisView Component Integration', () => {
  const mockLlmResponse = {
    threat_summary: 'Adversaries use ADFind to discover Active Directory structure, trust relationships, and privileged objects.',
    mitre_tactics: ['Discovery', 'Reconnaissance'],
    mitre_techniques: [
      {
        technique_id: 'T1087.002',
        technique_name: 'Domain Account Discovery',
        tactic: 'Discovery',
      },
      {
        technique_id: 'T1482',
        technique_name: 'Domain Trust Discovery',
        tactic: 'Discovery',
      },
    ],
    evasion_blindspots: [
      'Renaming the adfind.exe binary to bypass filename detection',
      'Encoding LDAP query parameters to hide filter syntax',
      'Invoking reconnaissance through reflective DLL injection',
    ],
    triage_questions: [
      'What user account initiated the ADFind query?',
      'Is the initiating host an authorized administrative jump host?',
      'Did the process attempt multiple LDAP queries within a 5-minute window?',
    ],
  };

  it('parses and renders MITRE ATT&CK tactics and techniques from LLM response', () => {
    render(<ThreatAnalysisView analysis={mockLlmResponse as any} />);

    // MITRE ATT&CK Section Header
    expect(screen.getByText(/MITRE ATT&CK/i)).toBeInTheDocument();

    // Tactics rendered
    expect(screen.getByText('Discovery')).toBeInTheDocument();
    expect(screen.getByText('Reconnaissance')).toBeInTheDocument();

    // Techniques rendered
    expect(screen.getByText('T1087.002')).toBeInTheDocument();
    expect(screen.getByText('Domain Account Discovery')).toBeInTheDocument();
    expect(screen.getByText('T1482')).toBeInTheDocument();
    expect(screen.getByText('Domain Trust Discovery')).toBeInTheDocument();
  });

  it('renders the "Evasion Blindspots" list', () => {
    render(<ThreatAnalysisView analysis={mockLlmResponse as any} />);

    // Must render the exact section title "Evasion Blindspots"
    expect(screen.getByText('Evasion Blindspots')).toBeInTheDocument();

    // Must render the list items
    expect(screen.getByText('Renaming the adfind.exe binary to bypass filename detection')).toBeInTheDocument();
    expect(screen.getByText('Encoding LDAP query parameters to hide filter syntax')).toBeInTheDocument();
    expect(screen.getByText('Invoking reconnaissance through reflective DLL injection')).toBeInTheDocument();
  });

  it('renders the "Tier 1 Triage Steps" list containing actionable investigation questions', () => {
    render(<ThreatAnalysisView analysis={mockLlmResponse as any} />);

    // Must render the exact section title "Tier 1 Triage Steps"
    expect(screen.getByText('Tier 1 Triage Steps')).toBeInTheDocument();

    // Must render the actionable triage questions
    expect(screen.getByText('What user account initiated the ADFind query?')).toBeInTheDocument();
    expect(screen.getByText('Is the initiating host an authorized administrative jump host?')).toBeInTheDocument();
    expect(screen.getByText('Did the process attempt multiple LDAP queries within a 5-minute window?')).toBeInTheDocument();
  });

  it('successfully parses raw LLM JSON string and renders sections', () => {
    const rawJsonString = JSON.stringify(mockLlmResponse);
    render(<ThreatAnalysisView analysis={rawJsonString as any} />);

    expect(screen.getByText('Evasion Blindspots')).toBeInTheDocument();
    expect(screen.getByText('Tier 1 Triage Steps')).toBeInTheDocument();
    expect(screen.getByText('T1087.002')).toBeInTheDocument();
  });
});

