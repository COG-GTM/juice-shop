/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('HTTP', () => {
  void it('response must echo CORS header for the configured base URL origin', async () => {
    const origin = config.get<string>('server.baseUrl')
    const res = await request(app).get('/rest/languages').set('Origin', origin)
    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], origin)
  })

  void it('response must not contain CORS header for an untrusted origin', async () => {
    const res = await request(app).get('/rest/languages').set('Origin', 'https://attacker.example')
    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], undefined)
  })

  void it('preflight request from an untrusted origin is not granted CORS access', async () => {
    const res = await request(app).options('/rest/languages')
      .set('Origin', 'https://attacker.example')
      .set('Access-Control-Request-Method', 'POST')
    assert.equal(res.headers['access-control-allow-origin'], undefined)
  })

  void it('Content-Security-Policy is report-only outside production to keep XSS challenges solvable', async () => {
    const res = await request(app).get('/')
    assert.equal(res.headers['content-security-policy'], undefined)
    assert.ok(res.headers['content-security-policy-report-only'])
  })

  void it('response must contain a Content-Security-Policy without inline script allowance', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    const csp = String(res.headers['content-security-policy-report-only'])
    assert.match(csp, /default-src 'self'/)
    assert.match(csp, /object-src 'none'/)
    assert.match(csp, /frame-ancestors 'self'/)
    assert.doesNotMatch(csp.split(';').find(directive => directive.trim().startsWith('script-src')) ?? '', /'unsafe-inline'|'unsafe-eval'|\*/)
  })

  void it('API responses must carry the Content-Security-Policy as well', async () => {
    const res = await request(app).get('/rest/languages')
    assert.match(String(res.headers['content-security-policy-report-only']), /script-src 'self'/)
  })

  void it('promotion video page CSP allows only its own inline script', async () => {
    const res = await request(app).get('/promotion')
    assert.equal(res.status, 200)
    assert.match(String(res.headers['content-security-policy-report-only']), /script-src 'self' 'sha256-[A-Za-z0-9+/=]+'/)
  })

  void it('response must disable the legacy XSS auditor', async () => {
    const res = await request(app).get('/')
    assert.equal(res.headers['x-xss-protection'], '0')
  })

  void it('response must contain sameorigin frameguard header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN')
  })

  void it('response must contain nosniff header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
  })

  void it('response must not contain recruiting header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-recruiting'], config.get('application.securityTxt.hiring'))
  })

  void it('unexpected path under known sub-path caught by generic error handler', async () => {
    const res = await request(app).get('/rest/x')
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('<title>Error: Unexpected path: /rest/x</title>'))
  })
})
