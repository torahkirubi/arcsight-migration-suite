import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import App, { AppContent } from './App';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Mock fetch for health checks and components
vi.stubGlobal(
  'fetch',
  vi.fn().mockImplementation((url: string) => {
    if (url.includes('/api/health')) {
      return Promise.resolve({
        ok: true,
        json: async () => ({ status: 'healthy', services: { fastapi: { status: 'online' } } }),
      });
    }
    return Promise.resolve({
      ok: true,
      json: async () => ({}),
    });
  })
);

const renderWithQueryClient = (component: React.ReactElement) => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      {component}
    </QueryClientProvider>
  );
};

describe('App Component & Tab Navigation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  it('renders LoginGate when auth token is missing', () => {
    renderWithQueryClient(<AppContent />);

    expect(screen.getByText(/Security Operations Login/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Secure Login/i })).toBeInTheDocument();
  });

  it('renders main navigation tabs when authenticated', () => {
    sessionStorage.setItem('auth_token', 'mock-jwt-token');

    renderWithQueryClient(<AppContent />);

    expect(screen.getByRole('button', { name: /^Translate$/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Live Tuning/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Settings/i })).toBeInTheDocument();
  });

  it('switches to StandaloneTuningView when Live Tuning tab is clicked', () => {
    sessionStorage.setItem('auth_token', 'mock-jwt-token');

    renderWithQueryClient(<AppContent />);

    // Click "Live Tuning" tab
    const tuningTab = screen.getByRole('button', { name: /Live Tuning/i });
    fireEvent.click(tuningTab);

    // Assert StandaloneTuningView elements are displayed
    expect(screen.getByRole('button', { name: /Analyze Telemetry/i })).toBeInTheDocument();
    expect(screen.getByLabelText(/Raw KQL Query/i)).toBeInTheDocument();
  });

  it('switches to IntegrationSettings when Settings tab is clicked', () => {
    sessionStorage.setItem('auth_token', 'mock-jwt-token');

    renderWithQueryClient(<AppContent />);

    // Click "Settings" tab
    const settingsTab = screen.getByRole('button', { name: /Settings/i });
    fireEvent.click(settingsTab);

    expect(screen.getByText(/Microsoft Sentinel Integration/i)).toBeInTheDocument();
  });

  it('renders Logout button when authenticated', () => {
    sessionStorage.setItem('auth_token', 'mock-jwt-token');

    renderWithQueryClient(<AppContent />);

    expect(screen.getByRole('button', { name: /Logout/i })).toBeInTheDocument();
  });

  it('removes token from storage and drops user to LoginGate when Logout is clicked', () => {
    sessionStorage.setItem('auth_token', 'mock-jwt-token');
    localStorage.setItem('auth_token', 'mock-jwt-token');

    renderWithQueryClient(<AppContent />);

    const logoutBtn = screen.getByRole('button', { name: /Logout/i });
    expect(logoutBtn).toBeInTheDocument();

    fireEvent.click(logoutBtn);

    // Verify tokens were cleared from both storage locations
    expect(sessionStorage.getItem('auth_token')).toBeNull();
    expect(localStorage.getItem('auth_token')).toBeNull();

    // Verify application immediately drops user back to LoginGate
    expect(screen.getByText(/Security Operations Login/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Secure Login/i })).toBeInTheDocument();
  });
});

