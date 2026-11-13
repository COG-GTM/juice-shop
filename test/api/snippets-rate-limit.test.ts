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

process.env.NODE_ENV = 'test'

void describe('/snippets rate limiting', () => {
  void it('answers with 429 once 300 requests per window are exceeded across all snippet routes, regardless of X-Forwarded-For', async () => {
    for (let i = 0; i < 100; i++) {
      assert.equal((await request(app).get('/snippets/loginAdminChallenge').set('X-Forwarded-For', `10.0.${i}.1`)).status, 200)
      assert.equal((await request(app).get('/snippets/fixes/loginAdminChallenge').set('X-Forwarded-For', `10.0.${i}.2`)).status, 200)
      assert.equal((await request(app).post('/snippets/verdict').set('X-Forwarded-For', `10.0.${i}.3`).send({ key: 'loginAdminChallenge', selectedLines: [] })).status, 200)
    }

    const limited = [
      await request(app).get('/snippets/loginAdminChallenge').set('X-Forwarded-For', '192.0.2.1'),
      await request(app).get('/snippets/fixes/loginAdminChallenge'),
      await request(app).post('/snippets/verdict').send({ key: 'loginAdminChallenge', selectedLines: [] }),
      await request(app).post('/snippets/fixes').send({ key: 'loginAdminChallenge', selectedFix: 0 })
    ]
    for (const res of limited) {
      assert.equal(res.status, 429)
    }
  })
})
