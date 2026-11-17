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
  void it('response must allow CORS for a configured trusted origin', async () => {
    const res = await request(app).get('/').set('Origin', 'http://localhost:4200')
    assert.equal(res.status, 200)
    assert.equal(res.headers['access-control-allow-origin'], 'http://localhost:4200')
  })

  void it('response must not allow CORS for an untrusted origin', async () => {
    const res = await request(app).get('/rest/user/whoami').set('Origin', 'https://evil.example')
    assert.equal(res.headers['access-control-allow-origin'], undefined)
  })

  void it('preflight request must not allow CORS for an untrusted origin', async () => {
    const res = await request(app).options('/api/Users').set('Origin', 'https://evil.example').set('Access-Control-Request-Method', 'POST')
    assert.equal(res.headers['access-control-allow-origin'], undefined)
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
