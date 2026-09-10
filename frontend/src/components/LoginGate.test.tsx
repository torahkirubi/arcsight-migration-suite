import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LoginGate } from './LoginGate';

describe('LoginGate Component', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
  });

  it('renders username and password input fields and a Secure Login button', () => {
    render(<LoginGate onLoginSuccess={vi.fn()} />);

    expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Secure Login/i })).toBeInTheDocument();
  });

  it('submits valid credentials, stores returned JWT in sessionStorage, and triggers onLoginSuccess', async () => {
    const onLoginSuccess = vi.fn();
    const mockToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mockTokenPayload.signature';

    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ access_token: mockToken, token_type: 'bearer' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<LoginGate onLoginSuccess={onLoginSuccess} />);

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'valid_password_123' } });

    fireEvent.click(screen.getByRole('button', { name: /Secure Login/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/login'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({
            username: 'admin',
            password: 'valid_password_123',
          }),
        })
      );
    });

    await waitFor(() => {
      const storedToken = sessionStorage.getItem('auth_token') || sessionStorage.getItem('token');
      expect(storedToken).toBe(mockToken);
      expect(onLoginSuccess).toHaveBeenCalledWith(mockToken);
    });
  });

  it('handles 401 Unauthorized and displays an error badge without crashing', async () => {
    const onLoginSuccess = vi.fn();

    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Invalid username or password' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<LoginGate onLoginSuccess={onLoginSuccess} />);

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'admin' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'wrong_password' } });

    fireEvent.click(screen.getByRole('button', { name: /Secure Login/i }));

    await waitFor(() => {
      expect(screen.getByText(/Invalid username or password/i)).toBeInTheDocument();
    });

    expect(onLoginSuccess).not.toHaveBeenCalled();
    expect(sessionStorage.getItem('auth_token')).toBeNull();
  });

  it('renders a "Create Account" button that toggles the form into registration mode with "Register Securely"', () => {
    render(<LoginGate onLoginSuccess={vi.fn()} />);

    const toggleButton = screen.getByRole('button', { name: /create account/i });
    expect(toggleButton).toBeInTheDocument();

    fireEvent.click(toggleButton);

    expect(screen.getByRole('button', { name: /register securely/i })).toBeInTheDocument();
  });

  it('submits registration to /api/auth/register, displays success message, and toggles back to login mode', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 201,
      json: async () => ({ username: 'new_analyst', status: 'created' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<LoginGate onLoginSuccess={vi.fn()} />);

    // Toggle into registration mode
    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'new_analyst' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'ValidPassword123!' } });

    fireEvent.click(screen.getByRole('button', { name: /register securely/i }));

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/register'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
          }),
          body: JSON.stringify({
            username: 'new_analyst',
            password: 'ValidPassword123!',
          }),
        })
      );
    });

    await waitFor(() => {
      expect(screen.getByText(/account created|registered successfully|success/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /secure login/i })).toBeInTheDocument();
    });
  });

  it('handles 400 Bad Request and renders "Username already registered" error badge without crashing', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      json: async () => ({ detail: 'Username already registered' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<LoginGate onLoginSuccess={vi.fn()} />);

    // Toggle into registration mode
    fireEvent.click(screen.getByRole('button', { name: /create account/i }));

    fireEvent.change(screen.getByLabelText(/username/i), { target: { value: 'existing_user' } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: 'SomePassword123!' } });

    fireEvent.click(screen.getByRole('button', { name: /register securely/i }));

    await waitFor(() => {
      expect(screen.getByText(/username already registered/i)).toBeInTheDocument();
    });
  });
});

