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

void describe('/rest/2fa/verify rate limit', () => {
  void it('POST should be rate limited even when X-Forwarded-For changes on every request', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .post('/rest/2fa/verify')
        .set({ 'content-type': 'application/json', 'X-Forwarded-For': `10.0.${Math.floor(i / 256)}.${i % 256}` })
        .send({ tmpToken: 'invalid', totpToken: '123456' })
      assert.equal(res.status, 401)
    }

    const res = await request(app)
      .post('/rest/2fa/verify')
      .set({ 'content-type': 'application/json', 'X-Forwarded-For': '10.1.0.1' })
      .send({ tmpToken: 'invalid', totpToken: '123456' })

    assert.equal(res.status, 429)
  })
})
