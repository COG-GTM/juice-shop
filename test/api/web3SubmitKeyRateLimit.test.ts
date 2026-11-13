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

void describe('/rest/web3/submitKey rate limiting', () => {
  void it('POST is rejected with 429 after 100 attempts within the window, even with rotating X-Forwarded-For', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/web3/submitKey')
        .set('X-Forwarded-For', `198.51.100.${i % 250}`)
        .send({ privateKey: `guess-${i}` })
      assert.equal(res.status, 401)
    }

    const res = await request(app)
      .post('/rest/web3/submitKey')
      .set('X-Forwarded-For', '203.0.113.7')
      .send({ privateKey: 'guess-100' })
    assert.equal(res.status, 429)
    assert.equal(res.body.message, 'Too many requests, please try again later.')
  })
})
