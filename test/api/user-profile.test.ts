/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import config from 'config'
import { createTestApp } from './helpers/setup'
import { login } from './helpers/auth'
import { PROFILE_CSP } from '../../routes/userProfile'

let app: Express
let authHeader: { Cookie: string }

before(async () => {
  const result = await createTestApp()
  app = result.app
  const { token } = await login(app, { email: 'jim@juice-sh.op', password: 'ncc-1701' })
  authHeader = { Cookie: `token=${token}` }
}, { timeout: 60000 })

void describe('/profile', () => {
  void it('GET user profile is forbidden for unauthenticated user', async () => {
    const res = await request(app)
      .get('/profile')

    assert.equal(res.status, 500)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes(`<h1>${config.get<string>('application.name')} (Express`))
    assert.ok(res.text.includes('Error: Blocked illegal activity'))
  })

  void it('GET user profile of authenticated user', async () => {
    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(res.headers['content-type']?.includes('text/html'))
    assert.ok(res.text.includes('id="email" type="email" name="email" value="jim@juice-sh.op"'))
  })

  void it('POST update username of authenticated user', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .field('username', 'Localhorst')
      .redirects(0)

    assert.equal(res.status, 302)
  })

  void it('POST update username is blocked for cross-origin requests', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Origin', 'https://attacker.example')
      .type('form')
      .send({ username: 'CSRF' })
      .redirects(0)

    assert.equal(res.status, 403)

    const profile = await request(app)
      .get('/profile')
      .set(authHeader)
    assert.ok(!profile.text.includes('CSRF'))
  })

  void it('POST update username is allowed for same-origin requests', async () => {
    const res = await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .set('Host', 'juice.example')
      .set('Origin', 'http://juice.example')
      .type('form')
      .send({ username: 'SameOrigin' })
      .redirects(0)

    assert.equal(res.status, 302)
    assert.ok(res.headers['set-cookie']?.[0].includes('SameSite=Lax'))
  })

  void it('GET user profile renders username as escaped text', async () => {
    await request(app)
      .post('/profile')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ username: '<<a|ascript>alert(`xss`)</script>' })
      .redirects(0)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.ok(!res.text.includes('<script>alert'))
  })

  void it('GET user profile CSP is not affected by the profile image URL', async () => {
    const upload = await request(app)
      .post('/profile/image/url')
      .set('Cookie', authHeader.Cookie)
      .type('form')
      .send({ imageUrl: "https://a.png; script-src 'unsafe-inline' 'self' 'unsafe-eval'" })
      .redirects(0)
    assert.equal(upload.status, 302)

    const res = await request(app)
      .get('/profile')
      .set(authHeader)

    assert.equal(res.status, 200)
    assert.equal(res.headers['content-security-policy'], PROFILE_CSP)
    assert.ok(!res.text.includes('unsafe-inline'))
  })
})
