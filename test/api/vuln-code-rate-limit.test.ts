/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/snippets rate limiting', () => {
  void it('rejects requests beyond 300 per window with 429, regardless of X-Forwarded-For', async () => {
    for (let i = 0; i < 300; i++) {
      const res = await request(app).get('/snippets/fixes/doesNotExistChallenge').set('X-Forwarded-For', `10.0.${i % 256}.${Math.floor(i / 256)}`)
      assert.equal(res.status, 404)
    }
    for (const req of [
      request(app).get('/snippets/loginAdminChallenge').set('X-Forwarded-For', '192.0.2.1'),
      request(app).get('/snippets/fixes/loginAdminChallenge'),
      request(app).post('/snippets/verdict').send({ key: 'loginAdminChallenge', selectedLines: [] }),
      request(app).post('/snippets/fixes').send({ key: 'loginAdminChallenge', selectedFix: 0 })
    ]) {
      const res = await req
      assert.equal(res.status, 429)
    }
  })
})
