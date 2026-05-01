import { describe, it, expect } from 'vitest'
import {
  CHAT_TOOL_DESCRIPTOR,
  CHAT_TOOL_NAME,
  formatToolResult,
  parseChatToolArgs,
} from '../src/server.js'
import type { AnthropicResponseBody } from '../src/types.js'

describe('CHAT_TOOL_DESCRIPTOR', () => {
  it('uses the canonical tool name', () => {
    expect(CHAT_TOOL_NAME).toBe('chat_via_lucairn')
    expect(CHAT_TOOL_DESCRIPTOR.name).toBe('chat_via_lucairn')
  })

  it('declares model + max_tokens + messages as required inputs', () => {
    const required = CHAT_TOOL_DESCRIPTOR.inputSchema.required
    expect(required).toContain('model')
    expect(required).toContain('max_tokens')
    expect(required).toContain('messages')
  })
})

describe('parseChatToolArgs', () => {
  it('accepts a well-formed call', () => {
    const out = parseChatToolArgs({
      model: 'claude-sonnet-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: 'hello' }],
    })
    expect(out.model).toBe('claude-sonnet-4-6')
    expect(out.max_tokens).toBe(512)
    expect(out.messages).toHaveLength(1)
  })

  it('rejects missing model', () => {
    expect(() =>
      parseChatToolArgs({
        max_tokens: 256,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    ).toThrow(/model/)
  })

  it('rejects non-positive max_tokens', () => {
    expect(() =>
      parseChatToolArgs({
        model: 'm',
        max_tokens: 0,
        messages: [{ role: 'user', content: 'hi' }],
      }),
    ).toThrow(/max_tokens/)
  })

  it('rejects empty messages', () => {
    expect(() =>
      parseChatToolArgs({
        model: 'm',
        max_tokens: 1,
        messages: [],
      }),
    ).toThrow(/messages/)
  })

  it('rejects non-object input', () => {
    expect(() => parseChatToolArgs(null)).toThrow()
    expect(() => parseChatToolArgs('hi')).toThrow()
  })
})

describe('formatToolResult', () => {
  const baseResp: AnthropicResponseBody = {
    id: 'msg_dsa_abc',
    type: 'message',
    role: 'assistant',
    content: [
      { type: 'text', text: 'Hello world' },
      { type: 'text', text: '. Have a nice day.' },
    ],
    model: 'claude-sonnet-4-6',
    stop_reason: 'end_turn',
    usage: { input_tokens: 10, output_tokens: 7 },
  }

  it('joins text content blocks into one MCP text result', () => {
    const out = formatToolResult(baseResp)
    expect(out.content).toHaveLength(1)
    expect(out.content[0]).toMatchObject({
      type: 'text',
      text: 'Hello world. Have a nice day.',
    })
  })

  it('appends a Lucairn certificate URL when present in metadata', () => {
    const out = formatToolResult({
      ...baseResp,
      metadata: {
        dsa_compliance: {
          request_id: 'abc',
          veil_summary_url: 'https://gateway.lucairn.eu/api/v1/veil/certificate/abc/summary',
          redaction_count: 0,
          latency_ms: 100,
        },
      },
    })
    expect(out.content[0].text).toContain('Lucairn certificate:')
    expect(out.content[0].text).toContain('certificate/abc/summary')
  })

  it('omits the certificate trailer when metadata is missing', () => {
    const out = formatToolResult(baseResp)
    expect(out.content[0].text).not.toContain('Lucairn certificate:')
  })
})
