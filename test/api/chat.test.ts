/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as http from 'http'
import crypto from 'node:crypto'
import config from 'config'
import * as security from '../../lib/insecurity'
import { ordersCollection } from '../../data/mongodb'
import { login } from './helpers/auth'
import { createTestApp } from './helpers/setup'

const MOCK_LLM_PORT = 43210

let app: Express
let mockServer: http.Server
let onLlmRequest: (req: http.IncomingMessage, body: string, res: http.ServerResponse) => void = (_req, _body, res) => {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end('{}')
}

function sseData (obj: object): string {
  return `data: ${JSON.stringify(obj)}\n\n`
}

function contentChunk (content: string): object {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'test-model',
    choices: [{ index: 0, delta: { content }, finish_reason: null }]
  }
}

function toolCallChunk (id: string, name: string, args: string): object {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'test-model',
    choices: [{
      index: 0,
      delta: {
        tool_calls: [{ index: 0, id, type: 'function', function: { name, arguments: args } }]
      },
      finish_reason: null
    }]
  }
}

function finishChunk (reason: string = 'stop'): object {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model: 'test-model',
    choices: [{ index: 0, delta: {}, finish_reason: reason }]
  }
}

function sendSSE (res: http.ServerResponse, chunks: object[]): void {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'close'
  })
  for (const chunk of chunks) {
    res.write(sseData(chunk))
  }
  res.write('data: [DONE]\n\n')
  res.end()
}

function orderLookupLlm (orderId: string, capture: { toolResult?: string }) {
  let callCount = 0
  return (_req: http.IncomingMessage, body: string, res: http.ServerResponse) => {
    callCount++
    if (callCount === 1) {
      sendSSE(res, [toolCallChunk('call_order', 'getOrderById', JSON.stringify({ orderId })), finishChunk('tool_calls')])
    } else {
      const toolMsg = JSON.parse(body).messages.find((m: { role: string }) => m.role === 'tool')
      capture.toolResult = typeof toolMsg?.content === 'string' ? toolMsg.content : JSON.stringify(toolMsg?.content)
      sendSSE(res, [contentChunk('Here is what I found.'), finishChunk()])
    }
  }
}

async function lookupOrderVia (authorization: string | undefined, orderId: string) {
  const capture: { toolResult?: string } = {}
  onLlmRequest = orderLookupLlm(orderId, capture)
  const headers: Record<string, string> = { 'content-type': 'application/json' }
  if (authorization) headers.Authorization = authorization
  const res = await request(app)
    .post('/rest/chat')
    .set(headers)
    .send({ messages: [{ role: 'user', content: `Where is my order ${orderId}?` }] })
  assert.equal(res.status, 200)
  return capture.toolResult ?? ''
}

function base64url (value: object) {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

const adminEmail = 'admin@' + config.get<string>('application.domain')
const adminPayload = { status: 'success', data: { id: 1, email: adminEmail, role: 'admin' }, iat: Math.floor(Date.now() / 1000) }

async function adminOrderId () {
  const order = await ordersCollection.findOne({ email: adminEmail.replace(/[aeiou]/gi, '*') })
  return order.orderId as string
}

before(async () => {
  await new Promise<void>((resolve) => {
    mockServer = http.createServer((req, res) => {
      let body = ''
      req.on('data', (chunk: Buffer) => { body += chunk.toString() })
      req.on('end', () => {
        onLlmRequest(req, body, res)
      })
    })
    mockServer.keepAliveTimeout = 0
    mockServer.listen(MOCK_LLM_PORT, resolve)
  })
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

after(async () => {
  await new Promise<void>((resolve) => {
    if (!mockServer?.listening) {
      resolve()
      return
    }
    mockServer.close(() => { resolve() })
  })
})

void describe('/rest/chat', { timeout: 120000 }, () => {
  void it('POST returns streamed text content as SSE events', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [
        contentChunk('Hello'),
        contentChunk(' there!'),
        finishChunk()
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Hi' }] })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/event-stream'))
    assert.ok(res.text.includes('Hello'))
    assert.ok(res.text.includes(' there!'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST sets correct SSE response headers', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [contentChunk('Hi'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Hello' }] })

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/event-stream'))
    assert.ok(res.headers['cache-control']?.includes('no-cache'))
  })

  void it('POST includes system prompt and user messages in LLM request', { timeout: 15000 }, async () => {
    let parsedBody: any
    onLlmRequest = (_req, body, res) => {
      parsedBody = JSON.parse(body)
      sendSSE(res, [contentChunk('I am Juicy!'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'What is your name?' }] })

    assert.equal(res.status, 200)
    assert.equal(parsedBody.messages[0].role, 'system')
    assert.ok(parsedBody.messages[0].content.includes('Juicy'))
    assert.equal(parsedBody.messages[1].role, 'user')
    assert.equal(parsedBody.messages[1].content, 'What is your name?')
  })

  void it('POST sends searchProducts tool definition to LLM', { timeout: 15000 }, async () => {
    let parsedBody: any
    onLlmRequest = (_req, body, res) => {
      parsedBody = JSON.parse(body)
      sendSSE(res, [contentChunk('We have many products!'), finishChunk()])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'What products do you have?' }] })

    assert.equal(res.status, 200)
    assert.ok(parsedBody.tools)
    assert.equal(parsedBody.tools.length, 4)
    const toolNames = parsedBody.tools.map((t: { function: { name: string } }) => t.function.name)
    assert.ok(toolNames.includes('searchProducts'))
    assert.ok(toolNames.includes('generateCoupon'))
    assert.ok(toolNames.includes('getOrderById'))
  })

  void it('POST handles searchProducts tool call and returns follow-up response', { timeout: 15000 }, async () => {
    let callCount = 0
    onLlmRequest = (_req, body, res) => {
      callCount++
      if (callCount === 1) {
        sendSSE(res, [
          toolCallChunk('call_abc', 'searchProducts', '{"query":"apple"}'),
          finishChunk('tool_calls')
        ])
      } else {
        const parsed = JSON.parse(body)
        const toolMsg = parsed.messages.find((m: { role: string }) => m.role === 'tool')
        assert.ok(toolMsg)
        assert.equal(toolMsg.tool_call_id, 'call_abc')
        assert.ok(toolMsg.content.includes('Apple Juice'))
        sendSSE(res, [
          contentChunk('We have Apple Juice (1000ml) for $1.99!'),
          finishChunk()
        ])
      }
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Do you have apple juice?' }] })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('Apple Juice'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST handles LLM API error gracefully', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      res.writeHead(500, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({ error: { message: 'Internal server error' } }))
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Hi' }] })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('error'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST with empty messages returns error SSE stream', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [
        contentChunk('How can I help you?'),
        finishChunk()
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [] })

    assert.equal(res.status, 200)
    assert.ok(res.text.includes('error'))
    assert.ok(res.text.includes('data: [DONE]'))
  })

  void it('POST response SSE data lines contain valid JSON', { timeout: 15000 }, async () => {
    onLlmRequest = (_req, _body, res) => {
      sendSSE(res, [
        contentChunk('Test message'),
        finishChunk()
      ])
    }

    const res = await request(app)
      .post('/rest/chat')
      .set({ 'content-type': 'application/json' })
      .send({ messages: [{ role: 'user', content: 'Test' }] })

    assert.equal(res.status, 200)
    const dataLines = res.text.split('\n').filter((l: string) => l.startsWith('data: '))
    assert.ok(dataLines.length >= 2)
    for (const line of dataLines) {
      const data = line.slice(6)
      if (data === '[DONE]') continue
      const parsed = JSON.parse(data)
      assert.ok(parsed.choices)
      if (parsed.choices[0].finish_reason) continue
      assert.ok(parsed.choices[0].delta)
    }
  })

  void describe('getOrderById tool', () => {
    void it('rejects requests without a token', { timeout: 15000 }, async () => {
      const result = await lookupOrderVia(undefined, await adminOrderId())
      assert.ok(result.includes('Customer not authenticated'))
    })

    void it('rejects an unsigned alg:none token claiming another user id', { timeout: 15000 }, async () => {
      const forged = `${base64url({ alg: 'none', typ: 'JWT' })}.${base64url(adminPayload)}.`
      const result = await lookupOrderVia(`Bearer ${forged}`, await adminOrderId())
      assert.ok(result.includes('Customer not authenticated'))
      assert.ok(!result.includes('totalPrice'))
    })

    void it('rejects an HS256 token signed with the public key', { timeout: 15000 }, async () => {
      const signingInput = `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url(adminPayload)}`
      const signature = crypto.createHmac('sha256', security.publicKey).update(signingInput).digest('base64url')
      const result = await lookupOrderVia(`Bearer ${signingInput}.${signature}`, await adminOrderId())
      assert.ok(result.includes('Customer not authenticated'))
      assert.ok(!result.includes('totalPrice'))
    })

    void it('rejects a correctly signed token that was never issued as a session', { timeout: 15000 }, async () => {
      const result = await lookupOrderVia(`Bearer ${security.authorize({ data: { id: 1 } })}`, await adminOrderId())
      assert.ok(result.includes('Customer not authenticated'))
    })

    void it('returns the order to its owner', { timeout: 15000 }, async () => {
      const orderId = await adminOrderId()
      const { token } = await login(app, { email: adminEmail, password: 'admin123' })
      const result = await lookupOrderVia(`Bearer ${token}`, orderId)
      assert.ok(result.includes(orderId))
      assert.ok(result.includes('totalPrice'))
    })

    void it('refuses an order owned by another customer', { timeout: 15000 }, async () => {
      const { token } = await login(app, { email: 'jim@' + config.get<string>('application.domain'), password: 'ncc-1701' })
      const result = await lookupOrderVia(`Bearer ${token}`, await adminOrderId())
      assert.ok(result.includes('Order does not belong to the current customer'))
      assert.ok(!result.includes('totalPrice'))
    })

    void it('refuses an order to a customer whose email only differs from the owner in vowels', { timeout: 15000 }, async () => {
      const lookalikeEmail = 'edmin@' + config.get<string>('application.domain')
      assert.equal(lookalikeEmail.replace(/[aeiou]/gi, '*'), adminEmail.replace(/[aeiou]/gi, '*'))
      await request(app)
        .post('/api/Users')
        .set({ 'content-type': 'application/json' })
        .send({ email: lookalikeEmail, password: 'lookalike123', passwordRepeat: 'lookalike123' })
        .expect(201)
      const { token } = await login(app, { email: lookalikeEmail, password: 'lookalike123' })
      const result = await lookupOrderVia(`Bearer ${token}`, await adminOrderId())
      assert.ok(result.includes('Order does not belong to the current customer'))
      assert.ok(!result.includes('totalPrice'))
    })
  })
})
