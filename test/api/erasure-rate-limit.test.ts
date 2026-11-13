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
  void it('answers with 429 once a client exceeds 100 requests within the window', async () => {
    const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })

    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .get('/dataerasure/')
        .set({ Cookie: 'token=' + token })
      assert.equal(res.status, 200)
    }

    const limited = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + token })
    assert.equal(limited.status, 429)

    const limitedPost = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + token })
      .field('email', 'bjoern@owasp.org')
    assert.equal(limitedPost.status, 429)
  })
})
