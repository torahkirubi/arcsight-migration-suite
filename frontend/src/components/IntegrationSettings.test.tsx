import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { IntegrationSettings } from './IntegrationSettings';

describe('IntegrationSettings Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('renders input fields for Tenant ID, Client ID, Client Secret, Workspace ID and action buttons', () => {
    render(<IntegrationSettings />);

    expect(screen.getByLabelText(/Tenant ID/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Client ID/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Client Secret/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Workspace ID/i)).toBeInTheDocument();

    expect(screen.getByRole('button', { name: /Test Connection/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save Configuration/i })).toBeInTheDocument();
  });

  it('triggers connection test on "Test Connection" click and displays success indicator', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ success: true, message: 'Connection Successful' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<IntegrationSettings />);

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'tenant-123' } });
    fireEvent.change(screen.getByLabelText(/Client ID/i), { target: { value: 'client-456' } });
    fireEvent.change(screen.getByLabelText(/Client Secret/i), { target: { value: 'secret-789' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-abc' } });

    fireEvent.click(screen.getByRole('button', { name: /Test Connection/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/settings/sentinel/test'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            client_id: 'client-456',
            client_secret: 'secret-789',
            workspace_id: 'workspace-abc',
          }),
        })
      );
    });

    await waitFor(() => {
      expect(screen.getByText(/Connection Successful/i)).toBeInTheDocument();
    });
  });

  it('triggers credential save on "Save Configuration" click', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'success', success: true, message: 'Credentials saved' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<IntegrationSettings />);

    fireEvent.change(screen.getByLabelText(/Tenant ID/i), { target: { value: 'tenant-123' } });
    fireEvent.change(screen.getByLabelText(/Client ID/i), { target: { value: 'client-456' } });
    fireEvent.change(screen.getByLabelText(/Client Secret/i), { target: { value: 'secret-789' } });
    fireEvent.change(screen.getByLabelText(/Workspace ID/i), { target: { value: 'workspace-abc' } });

    fireEvent.click(screen.getByRole('button', { name: /Save Configuration/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/settings/sentinel'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({
            tenant_id: 'tenant-123',
            client_id: 'client-456',
            client_secret: 'secret-789',
            workspace_id: 'workspace-abc',
          }),
        })
      );
    });
  });
});

