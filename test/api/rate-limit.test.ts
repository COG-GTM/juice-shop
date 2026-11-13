/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before, after } from 'node:test'
import assert from 'node:assert/strict'
import type { Server } from 'node:http'
import request from 'supertest'
import { createTestApp } from './helpers/setup'

const requestsPerWindow = 1000

let server: Server

before(async () => {
  const { app } = await createTestApp()
  server = app.listen(0)
}, { timeout: 60000 })

after(() => {
  server.close()
})

void describe('API rate limiting', () => {
  void it('answers authorization-checked routes normally until the per-client ceiling is reached', async () => {
    for (let i = 0; i < requestsPerWindow; i++) {
      const res = await request(server).get('/rest/2fa/status')
      assert.equal(res.status, 401)
    }
  })

  void it('rejects further requests from the same client with 429', async () => {
    const res = await request(server).get('/rest/2fa/status')
    assert.equal(res.status, 429)
    const profile = await request(server).get('/profile')
    assert.equal(profile.status, 429)
  })

  void it('cannot be bypassed by spoofing X-Forwarded-For', async () => {
    const res = await request(server)
      .get('/rest/2fa/status')
      .set('X-Forwarded-For', '203.0.113.7')
    assert.equal(res.status, 429)
  })
})
