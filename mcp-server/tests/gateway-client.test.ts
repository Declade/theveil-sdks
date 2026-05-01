import { describe, it, expect, vi } from 'vitest'
import { GatewayClient, buildMessagesRequestBody } from '../src/gateway-client.js'
import { GatewayError } from '../src/types.js'

const baseInput = {
  model: 'claude-sonnet-4-6',
  max_tokens: 256,
  messages: [{ role: 'user' as const, content: 'hi' }],
}

function fakeResponse(status: number, body: string): Response {
  return new Response(body, {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('buildMessagesRequestBody', () => {
  it('forces stream:false and forwards the optional system + temperature', () => {
    const body = buildMessagesRequestBody({
      ...baseInput,
      system: 'helpful',
      temperature: 0.7,
    })
    expect(body.stream).toBe(false)
    expect(body.model).toBe('claude-sonnet-4-6')
    expect(body.max_tokens).toBe(256)
    expect(body.system).toBe('helpful')
    expect(body.temperature).toBe(0.7)
  })

  it('omits system and temperature when not provided', () => {
    const body = buildMessagesRequestBody(baseInput)
    expect(body).not.toHaveProperty('system')
    expect(body).not.toHaveProperty('temperature')
  })
})

describe('GatewayClient.sendMessage', () => {
  it('forwards x-api-key and optional X-Upstream-Key headers', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(
      fakeResponse(
        200,
        JSON.stringify({
          id: 'msg_dsa_abc',
          type: 'message',
          role: 'assistant',
          content: [{ type: 'text', text: 'ok' }],
          model: 'claude-sonnet-4-6',
          stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 },
        }),
      ),
    )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu/',
      upstreamKey: 'sk-ant-xyz',
      fetchImpl: fetchSpy,
    })
    await client.sendMessage(baseInput)

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://gateway.lucairn.eu/api/v1/mcp/messages')
    expect(init.method).toBe('POST')
    const headers = init.headers as Record<string, string>
    expect(headers['x-api-key']).toBe('lcr_live_test')
    expect(headers['X-Upstream-Key']).toBe('sk-ant-xyz')
    expect(headers['content-type']).toBe('application/json')
  })

  it('parses and returns the gateway 200 body', async () => {
    const responseBody = {
      id: 'msg_dsa_xyz',
      type: 'message' as const,
      role: 'assistant' as const,
      content: [{ type: 'text', text: 'hello back' }],
      model: 'claude-sonnet-4-6',
      stop_reason: 'end_turn',
      usage: { input_tokens: 5, output_tokens: 3 },
      metadata: {
        dsa_compliance: {
          request_id: 'xyz',
          veil_summary_url: 'https://gateway.lucairn.eu/api/v1/veil/certificate/xyz/summary',
          redaction_count: 0,
          latency_ms: 1234,
        },
      },
    }
    const fetchSpy = vi
      .fn()
      .mockResolvedValue(fakeResponse(200, JSON.stringify(responseBody)))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    const out = await client.sendMessage(baseInput)
    expect(out).toEqual(responseBody)
  })

  it('maps a 503 with anthropic-error envelope to GatewayError', async () => {
    const errBody = {
      type: 'error',
      error: {
        type: 'api_error',
        message: 'Inference service unavailable. Retry after 30 seconds.',
      },
    }
    // Each call needs a fresh Response — Response.body is single-use.
    const fetchSpy = vi
      .fn()
      .mockImplementation(() =>
        Promise.resolve(fakeResponse(503, JSON.stringify(errBody))),
      )
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 503,
      errorType: 'api_error',
    })
    await expect(client.sendMessage(baseInput)).rejects.toBeInstanceOf(GatewayError)
  })

  it('maps a 401 without a parseable body to authentication_error', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(fakeResponse(401, 'Unauthorized'))
    const client = new GatewayClient({
      apiKey: 'lcr_live_bad',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 401,
      errorType: 'authentication_error',
    })
  })

  it('wraps fetch network errors as GatewayError with status 0', async () => {
    const fetchSpy = vi.fn().mockRejectedValue(new Error('ENOTFOUND'))
    const client = new GatewayClient({
      apiKey: 'lcr_live_test',
      baseUrl: 'https://gateway.lucairn.eu',
      fetchImpl: fetchSpy,
    })
    await expect(client.sendMessage(baseInput)).rejects.toMatchObject({
      name: 'GatewayError',
      status: 0,
      errorType: 'network_error',
    })
  })
})
