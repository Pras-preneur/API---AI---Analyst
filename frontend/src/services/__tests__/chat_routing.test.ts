import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { sendChatMessageToSLM } from '../chatService';

describe('Chat Routing & SLM Integration', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const testPrompts = [
    'Explain the difference between BOLA and BFLA.',
    'Explain HTTP 401 versus 403.',
    'Show a defensive Pydantic model against Mass Assignment.',
    'Prepare an executive security summary.',
    'Suggest CI/CD security assertions.',
  ];

  testPrompts.forEach((prompt) => {
    it(`routes prompt "${prompt}" to /api/v1/chat and returns contextual response`, async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          message: `Technical analysis for: ${prompt}`,
          reply: `Technical analysis for: ${prompt}`,
          intent: 'vulnerability_analysis',
          ui_actions: [{ type: 'none' }],
        }),
      } as Response);

      const result = await sendChatMessageToSLM(prompt, { specTitle: 'Test API' });
      expect(result.reply).toContain('Technical analysis');
      expect(globalThis.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/chat'),
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({ 'Content-Type': 'application/json' }),
          body: JSON.stringify({
            message: prompt,
            context: { specTitle: 'Test API' },
          }),
        })
      );
    });
  });

  it('passes X-Session-ID header and sessionId in context when active session is present', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        message: 'Live session answer',
        reply: 'Live session answer',
        intent: 'scanner_review',
        ui_actions: [{ type: 'none' }],
      }),
    } as Response);

    const result = await sendChatMessageToSLM('What endpoints have been discovered in my current session?', {
      specTitle: 'Live API',
      sessionId: 'sess-abc-123',
    });
    expect(result.reply).toBe('Live session answer');
    expect(globalThis.fetch).toHaveBeenCalledWith(
      expect.stringContaining('/api/v1/chat'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
          'X-Session-ID': 'sess-abc-123',
        }),
        body: JSON.stringify({
          message: 'What endpoints have been discovered in my current session?',
          context: { specTitle: 'Live API', sessionId: 'sess-abc-123' },
        }),
      })
    );
  });

  it('correctly handles local client fallback when backend SLM is unreachable', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));
    const result = await sendChatMessageToSLM('What is BOLA?', { specTitle: 'Banking API' });
    expect(result.reply).toContain('Broken Object Level Authorization');
    expect(result.intent).toBe('vulnerability_analysis');
  });
});
