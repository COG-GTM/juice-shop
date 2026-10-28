/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import * as security from '../../lib/insecurity'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

function verifyTotp (userId: number, forwardedFor: string) {
  return request(app)
    .post('/rest/2fa/verify')
    .set({ 'content-type': 'application/json', 'X-Forwarded-For': forwardedFor })
    .send({ tmpToken: security.authorize({ userId, type: 'password_valid_needs_second_factor_token' }), totpToken: '000000' })
}

void describe('/rest/2fa/verify rate limit', () => {
  void it('POST should rate limit guesses per account even when X-Forwarded-For changes on every request', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await verifyTotp(10, `10.0.${Math.floor(i / 256)}.${i % 256}`)
      assert.equal(res.status, 401)
    }

    const res = await verifyTotp(10, '10.1.0.1')
    assert.equal(res.status, 429)
  })

  void it('POST should not rate limit other accounts behind the same address', async () => {
    const res = await verifyTotp(1, '10.1.0.1')
    assert.equal(res.status, 401)
  })
})
