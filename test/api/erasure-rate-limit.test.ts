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
  void it('rejects anonymous requests beyond 100 per window even with rotating X-Forwarded-For headers', async () => {
    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .get('/dataerasure/')
        .set('X-Forwarded-For', `10.0.0.${i}`)
      assert.notEqual(res.status, 429)
    }

    const getRes = await request(app)
      .get('/dataerasure/')
      .set('X-Forwarded-For', '192.0.2.1')
    assert.equal(getRes.status, 429)

    const postRes = await request(app)
      .post('/dataerasure/')
      .set('X-Forwarded-For', '198.51.100.7')
    assert.equal(postRes.status, 429)
  })

  void it('limits logged-in users per account so users sharing an address are not blocked by each other', async () => {
    const { token: bjoernToken } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
    const { token: otherToken } = await login(app, { email: 'bjoern.kimminich@gmail.com', password: 'bW9jLmxpYW1nQGhjaW5pbW1pay5ucmVvamI=' })

    for (let i = 0; i < 100; i++) {
      const res = await request(app)
        .get('/dataerasure/')
        .set({ Cookie: 'token=' + bjoernToken })
      assert.equal(res.status, 200)
    }

    const limitedRes = await request(app)
      .get('/dataerasure/')
      .set({ Cookie: 'token=' + bjoernToken })
    assert.equal(limitedRes.status, 429)

    const otherRes = await request(app)
      .post('/dataerasure/')
      .set({ Cookie: 'token=' + otherToken })
      .field('email', 'bjoern.kimminich@gmail.com')
    assert.equal(otherRes.status, 200)
  })
})
