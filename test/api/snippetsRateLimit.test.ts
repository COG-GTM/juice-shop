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
  void it('exposes rate limit headers on all coding challenge routes', async () => {
    const responses = [
      await request(app).get('/snippets/resetPasswordBenderChallenge'),
      await request(app).post('/snippets/verdict').send({ key: 'resetPasswordBenderChallenge', selectedLines: [] }),
      await request(app).get('/snippets/fixes/resetPasswordBenderChallenge'),
      await request(app).post('/snippets/fixes').send({ key: 'resetPasswordBenderChallenge', selectedFix: 0 })
    ]
    for (const res of responses) {
      assert.equal(res.headers['ratelimit-limit'], '120')
    }
    assert.equal(responses[3].headers['ratelimit-remaining'], '116')
  })

  void it('shares one budget across the routes and rejects requests beyond it with 429, regardless of X-Forwarded-For', async () => {
    const first = await request(app).get('/snippets/fixes/doesNotExist')
    assert.equal(first.status, 404)
    const remaining = Number(first.headers['ratelimit-remaining'])
    for (let i = 0; i < remaining; i++) {
      const res = await request(app).get(`/snippets/fixes/doesNotExist${i}`)
      assert.equal(res.status, 404)
    }
    const blocked = [
      await request(app).get('/snippets/fixes/resetPasswordBenderChallenge'),
      await request(app).get('/snippets/resetPasswordBenderChallenge').set('X-Forwarded-For', '10.0.0.1'),
      await request(app).post('/snippets/verdict').set('X-Forwarded-For', '10.0.0.2').send({ key: 'resetPasswordBenderChallenge', selectedLines: [] }),
      await request(app).post('/snippets/fixes').set('X-Forwarded-For', '10.0.0.3').send({ key: 'resetPasswordBenderChallenge', selectedFix: 0 })
    ]
    for (const res of blocked) {
      assert.equal(res.status, 429)
      assert.ok(Number(res.headers['retry-after']) > 0)
    }
  })
})
