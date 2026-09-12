import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ModelSelector } from './ModelSelector';
import { LLMConfig } from '../api/client';

describe('ModelSelector Component', () => {
  const mockConfig: LLMConfig = {
    provider: 'cloud_openai',
    custom_base_url: 'https://api.openai.com/v1',
    model_name: 'gpt-4o',
    api_key: 'sk-test-key-12345',
  };

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('does not render when isOpen is false', () => {
    const { container } = render(
      <ModelSelector
        isOpen={false}
        onClose={vi.fn()}
        config={mockConfig}
        onChange={vi.fn()}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  it('renders provider options, base URL, model name, and API Key input when isOpen is true', () => {
    render(
      <ModelSelector
        isOpen={true}
        onClose={vi.fn()}
        config={mockConfig}
        onChange={vi.fn()}
      />
    );

    expect(screen.getByText(/Dual-Model Routing Engine/i)).toBeInTheDocument();
    expect(screen.getByText(/LM Studio/i)).toBeInTheDocument();
    expect(screen.getByText(/Cloud OpenAI/i)).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/sk-\.\.\./i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Save Key/i })).toBeInTheDocument();
  });

  it('switches provider when Gemini button is clicked', () => {
    const onChange = vi.fn();
    render(
      <ModelSelector
        isOpen={true}
        onClose={vi.fn()}
        config={mockConfig}
        onChange={onChange}
      />
    );

    const geminiBtn = screen.getByRole('button', { name: /Google Gemini/i });
    fireEvent.click(geminiBtn);

    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        provider: 'gemini',
        custom_base_url: 'https://generativelanguage.googleapis.com/v1beta/openai',
        model_name: 'gemini-2.5-flash',
      })
    );
  });

  it('persists API key to backend vault when Save Key is clicked and shows confirmation badge', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ success: true, message: 'cloud_openai key secured in vault' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(
      <ModelSelector
        isOpen={true}
        onClose={vi.fn()}
        config={mockConfig}
        onChange={vi.fn()}
      />
    );

    const saveBtn = screen.getByRole('button', { name: /Save Key/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/api/settings/llm',
        expect.objectContaining({
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            provider: 'cloud_openai',
            api_key: 'sk-test-key-12345',
            model_name: 'gpt-4o',
          }),
        })
      );
    });

    await waitFor(() => {
      expect(screen.getByText(/Key saved to Vault/i)).toBeInTheDocument();
    });
  });

  it('displays error feedback when key saving fails', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ detail: 'Vault encryption error' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    render(
      <ModelSelector
        isOpen={true}
        onClose={vi.fn()}
        config={mockConfig}
        onChange={vi.fn()}
      />
    );

    const saveBtn = screen.getByRole('button', { name: /Save Key/i });
    fireEvent.click(saveBtn);

    await waitFor(() => {
      expect(screen.getByText(/Vault encryption error/i)).toBeInTheDocument();
    });
  });

  it('hides API key field when LM Studio provider is selected', () => {
    const localConfig: LLMConfig = {
      provider: 'lm_studio',
      custom_base_url: 'http://localhost:1234/v1',
      model_name: 'qwen2.5-coder-7b-instruct',
    };

    render(
      <ModelSelector
        isOpen={true}
        onClose={vi.fn()}
        config={localConfig}
        onChange={vi.fn()}
      />
    );

    expect(screen.queryByPlaceholderText(/sk-\.\.\./i)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Save Key/i })).not.toBeInTheDocument();
  });
});
