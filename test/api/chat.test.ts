/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import request from 'supertest'
import type { Express } from 'express'
import * as http from 'http'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login, register } from './helpers/auth'
import { publicKey } from '../../lib/insecurity'

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

async function getOrderByIdToolResult (token: string, orderId: string): Promise<string> {
  let toolResult = ''
  onLlmRequest = (_req, body, res) => {
    let messages: Array<{ role: string, content?: string }> = []
    try {
      messages = JSON.parse(body).messages ?? []
    } catch {}
    const toolMsg = messages.find((m) => m.role === 'tool')
    if (toolMsg) {
      toolResult = toolMsg.content ?? ''
      sendSSE(res, [contentChunk('Here is what I found.'), finishChunk()])
    } else {
      sendSSE(res, [
        toolCallChunk('call_order', 'getOrderById', JSON.stringify({ orderId })),
        finishChunk('tool_calls')
      ])
    }
  }

  const res = await request(app)
    .post('/rest/chat')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({ messages: [{ role: 'user', content: `Show me order ${orderId}` }] })

  assert.equal(res.status, 200)
  return toolResult
}

function forgeToken (alg: string, payload: object): string {
  const b64 = (obj: object) => Buffer.from(JSON.stringify(obj)).toString('base64url')
  const unsigned = `${b64({ alg, typ: 'JWT' })}.${b64(payload)}`
  const signature = alg === 'none' ? '' : createHmac('sha256', publicKey).update(unsigned).digest('base64url')
  return `${unsigned}.${signature}`
}

async function systemPromptFor (token: string): Promise<string> {
  let systemPrompt = ''
  onLlmRequest = (_req, body, res) => {
    systemPrompt = JSON.parse(body).messages[0].content
    sendSSE(res, [contentChunk('Hi!'), finishChunk()])
  }

  const res = await request(app)
    .post('/rest/chat')
    .set({ Authorization: 'Bearer ' + token, 'content-type': 'application/json' })
    .send({ messages: [{ role: 'user', content: 'Who am I?' }] })

  assert.equal(res.status, 200)
  return systemPrompt
}

const bjoernGoogle = { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' }

function userIdOf (token: string): number {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()).data.id
}

async function firstAdminOrderId (adminToken: string): Promise<string> {
  const res = await request(app)
    .get('/rest/order-history')
    .set({ Authorization: 'Bearer ' + adminToken, 'content-type': 'application/json' })
  assert.equal(res.status, 200)
  return res.body.data[0].orderId
}

before(async () => {
  await new Promise<void>((resolve) => {
    mockServer = http.createServer((req, res) => {
      let body = ''
      req.on('data', (chunk: Buffer) => { body += chunk.toString() })
      req.on('end', () => {
        try {
          onLlmRequest(req, body, res)
        } catch {
          if (!res.headersSent) res.writeHead(500)
          res.end()
        }
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

  void it('POST getOrderById returns an order to its owner', { timeout: 15000 }, async () => {
    const { token } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    const orderId = await firstAdminOrderId(token)

    const toolResult = await getOrderByIdToolResult(token, orderId)

    assert.ok(toolResult.includes(orderId))
    assert.ok(toolResult.includes('Apple Juice (1000ml)'))
  })

  void it('POST getOrderById denies an account whose email only differs in vowels from the owner', { timeout: 15000 }, async () => {
    const domain = config.get<string>('application.domain')
    const { token: adminToken } = await login(app, { email: 'admin@' + domain, password: 'admin123' })
    const orderId = await firstAdminOrderId(adminToken)

    const lookalike = { email: 'edmin@' + domain, password: randomUUID() }
    await register(app, lookalike)
    const { token } = await login(app, lookalike)

    const toolResult = await getOrderByIdToolResult(token, orderId)

    assert.ok(toolResult.includes('Order does not belong to the current customer'))
    assert.ok(!toolResult.includes('Apple Juice (1000ml)'))
  })

  void it('POST getOrderById ignores an unsigned token that claims the owner\'s user id', { timeout: 15000 }, async () => {
    const { token: adminToken } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    const orderId = await firstAdminOrderId(adminToken)
    const forged = forgeToken('none', { data: { id: 1, email: 'admin@' + config.get<string>('application.domain') } })

    const toolResult = await getOrderByIdToolResult(forged, orderId)

    assert.ok(toolResult.includes('Customer not authenticated'))
    assert.ok(!toolResult.includes('Apple Juice (1000ml)'))
  })

  void it('POST getOrderById ignores an HS256 token signed with the public key that claims the owner\'s user id', { timeout: 15000 }, async () => {
    const { token: adminToken } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    const orderId = await firstAdminOrderId(adminToken)
    const forged = forgeToken('HS256', { data: { id: 1, email: 'admin@' + config.get<string>('application.domain') } })

    const toolResult = await getOrderByIdToolResult(forged, orderId)

    assert.ok(toolResult.includes('Customer not authenticated'))
    assert.ok(!toolResult.includes('Apple Juice (1000ml)'))
  })

  void it('POST names the customer from a verified token in the system prompt', { timeout: 15000 }, async () => {
    const { token } = await login(app, bjoernGoogle)

    assert.ok((await systemPromptFor(token)).includes('bkimminich'))
  })

  void it('POST does not name the customer from an unsigned token in the system prompt', { timeout: 15000 }, async () => {
    const { token } = await login(app, bjoernGoogle)
    const forged = forgeToken('none', { data: { id: userIdOf(token) } })

    assert.ok(!(await systemPromptFor(forged)).includes('bkimminich'))
  })

  void it('POST does not name the customer from an RS256 token with an empty signature in the system prompt', { timeout: 15000 }, async () => {
    const { token } = await login(app, bjoernGoogle)
    const [header, payload] = forgeToken('RS256', { data: { id: userIdOf(token) } }).split('.')

    assert.ok(!(await systemPromptFor(`${header}.${payload}.`)).includes('bkimminich'))
  })

  void it('POST getOrderById ignores an RS256 token with an empty signature that claims the owner\'s user id', { timeout: 15000 }, async () => {
    const { token: adminToken } = await login(app, { email: 'admin@' + config.get<string>('application.domain'), password: 'admin123' })
    const orderId = await firstAdminOrderId(adminToken)
    const [header, payload] = forgeToken('RS256', { data: { id: userIdOf(adminToken) } }).split('.')

    const toolResult = await getOrderByIdToolResult(`${header}.${payload}.`, orderId)

    assert.ok(toolResult.includes('Customer not authenticated'))
    assert.ok(!toolResult.includes('Apple Juice (1000ml)'))
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
})
