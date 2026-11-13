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
  void it('response must echo an allowed origin in the CORS header', async () => {
    const trustedOrigin = config.get<string>('server.baseUrl')
    const res = await request(app).get('/').set('Origin', trustedOrigin)
    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], trustedOrigin)
  })

  void it('response must not contain CORS header for an untrusted origin', async () => {
    const res = await request(app).get('/rest/products/search?q=').set('Origin', 'https://attacker.example')
    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], undefined)
  })

  void it('preflight from an untrusted origin must not be approved', async () => {
    const res = await request(app).options('/rest/memories').set('Origin', 'https://attacker.example').set('Access-Control-Request-Method', 'GET')
    assert.equal(res.status, 204)
    assert.equal(res.headers['access-control-allow-origin'], undefined)
    assert.equal(res.headers['access-control-allow-methods'], undefined)
  })

  void it('preflight from a trusted origin must be approved', async () => {
    const trustedOrigin = config.get<string>('server.baseUrl')
    const res = await request(app).options('/rest/memories').set('Origin', trustedOrigin).set('Access-Control-Request-Method', 'GET')
    assert.equal(res.status, 204)
    assert.equal(res.headers['access-control-allow-origin'], trustedOrigin)
  })

  void it('response must contain sameorigin frameguard header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN')
  })

  void it('response must contain nosniff content type options header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-content-type-options'], 'nosniff')
  })

  void it('response must not contain recruiting header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-recruiting'], config.get('application.securityTxt.hiring'))
  })

  void it('response must not contain XSS protection header', async () => {
    const res = await request(app).get('/')
    assert.equal(res.status, 200)
    assert.equal(res.headers['x-xss-protection'], undefined)
  })

  void it('unexpected path under known sub-path caught by generic error handler', async () => {
    const res = await request(app).get('/rest/x')
    assert.equal(res.status, 500)
    assert.ok(res.text.includes('<title>Error: Unexpected path: /rest/x</title>'))
  })
})
