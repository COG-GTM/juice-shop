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
let cookie: string

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'bjoern@owasp.org', password: 'kitten lesser pooch karate buffoon indoors' })
  cookie = `token=${token}`
}, { timeout: 60000 })

void describe('Profile and data erasure rate limiting', () => {
  void it('allows 100 requests per window across /profile and /dataerasure, then answers 429 even with spoofed X-Forwarded-For', async () => {
    for (let i = 0; i < 100; i++) {
      const path = i % 2 === 0 ? '/profile' : '/dataerasure/'
      const res = await request(app)
        .get(path)
        .set('Cookie', cookie)
        .set('X-Forwarded-For', `203.0.113.${i % 250}`)
      assert.equal(res.status, 200, `request ${i + 1} to ${path} should succeed`)
    }

    const getProfile = await request(app).get('/profile').set('Cookie', cookie).set('X-Forwarded-For', '198.51.100.1')
    assert.equal(getProfile.status, 429)

    const postProfile = await request(app).post('/profile').set('Cookie', cookie).field('username', 'ratelimited').redirects(0)
    assert.equal(postProfile.status, 429)

    const getErasure = await request(app).get('/dataerasure/').set('Cookie', cookie)
    assert.equal(getErasure.status, 429)

    const postErasure = await request(app).post('/dataerasure/').set('Cookie', cookie).type('form').send({ email: 'bjoern@owasp.org', securityAnswer: 'x' })
    assert.equal(postErasure.status, 429)

    const imageUrl = await request(app).post('/profile/image/url').set('Cookie', cookie).field('imageUrl', 'http://localhost/x.png').redirects(0)
    assert.equal(imageUrl.status, 429)
  })
})
