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

void describe('/rest/user/login rate limiting', () => {
  void it('allows 100 failed logins, rate limits the 101st and ignores X-Forwarded-For rotation', { timeout: 60000 }, async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/user/login')
        .set({ 'content-type': 'application/json' })
        .send({
          email: 'rate-limit-test@example.com',
          password: 'wrong-password'
        })

      assert.equal(res.status, 401)
    }

    const res = await request(app)
      .post('/rest/user/login')
      .set({ 'content-type': 'application/json' })
      .send({
        email: 'rate-limit-test@example.com',
        password: 'wrong-password'
      })

    assert.equal(res.status, 429)

    const rotatedRes = await request(app)
      .post('/rest/user/login')
      .set({
        'content-type': 'application/json',
        'X-Forwarded-For': '203.0.113.7'
      })
      .send({
        email: 'rate-limit-test@example.com',
        password: 'wrong-password'
      })

    assert.equal(rotatedRes.status, 429)
  })
})
