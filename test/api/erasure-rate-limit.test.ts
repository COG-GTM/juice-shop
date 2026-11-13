/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/dataerasure rate limiting', () => {
  void it('answers with 429 once a user exceeds 100 requests within the window, even when rotating X-Forwarded-For', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .get('/dataerasure/')
        .set({ Cookie: 'token=' + token, 'X-Forwarded-For': `10.0.${Math.floor(i / 256)}.${i % 256}` })
      assert.equal(res.status, 200)
    }

    const limited = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token, 'X-Forwarded-For': '10.1.0.1' })
    assert.equal(limited.status, 429)

    const limitedPost = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .field('email', 'bjoern@owasp.org')
    assert.equal(limitedPost.status, 429)
  })

  void it('keeps serving a different user from the same address', async () => {
    const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })

    const res = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })
    assert.equal(res.status, 200)
  })

  void it('limits anonymous clients by socket address regardless of X-Forwarded-For', async () => {
    for (let i = 0; i < 100; i++) {
      await request(app)
        .get('/dataerasure/')
        .set({ 'X-Forwarded-For': `10.2.${Math.floor(i / 256)}.${i % 256}` })
    }

    const limited = await request(app)
      .get('/dataerasure/')
      .set({ 'X-Forwarded-For': '10.3.0.1' })
    assert.equal(limited.status, 429)
  })
})
